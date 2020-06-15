#!/usr/bin/python

import getopt
import re
import sys

def usage():
    print('PostfixAnalyzer -f filename')

class PostfixLine:
    _name = ''
    _regEx = ''
    _handler = ''
    
    def __init__(self, name, regEx, handler):
        self._name = name
        self._regEx = re.compile(regEx)
        self._handler = handler

    def match(self, line):
        return self._regEx.search(line)
        

class PostfixTransaction:
    
    def __init__(self, date, ptr, ip):
        self._dateTime = date
        self._ptr = ptr
        self._ip = ip    
        self._host = ''
        self._helo = ''
        self._postfixID = ''
        self._messageID = ''
        self._postfixIDDelivery = ''
        self._from = ''
        self._to = ''
        self._status = ''
        self._size = ''
        self._relay = ''
        self._transport = ''
        self._result = ''
        self._delay = ''
        self._spamScore = ''
        self._spamDelay = ''
        self._spamReport = ''
        
class PostfixAnalyzer:

    _transactions = {}
    _transactionsSMTPD = {}
    _msgIDMap = {}
    _spamPIDMap = {}

    def __init__(self):
        self._reporter = None

        self._postfixIDMap = {}
        self._pidSMTPDMap = {}
        self._messageIDMap = {}
        self._pidSpamMap = {}

        self._lineDefs = []
        self._lineDefs.append(PostfixLine('start smtpd', 'postfix/smtpd.*connect from', self.onStart))
        self._lineDefs.append(PostfixLine('start noqueue', 'postfix/smtpd.*NOQUEUE', self.onNoQueue))
        self._lineDefs.append(PostfixLine('start queue', 'postfix/smtpd.*client=', self.onQueue))
        self._lineDefs.append(PostfixLine('removed', 'postfix/qmgr.*removed', self.onRemoved))
        self._lineDefs.append(PostfixLine('cleanup', 'postfix/cleanup', self.onCleanup))
        self._lineDefs.append(PostfixLine('queued', 'postfix/qmgr.*from=', self.onQueued))
        self._lineDefs.append(PostfixLine('spam', 'spamd', self.onSpam))
        self._lineDefs.append(PostfixLine('pipe', 'postfix/pipe', self.onPipe))
        self._lineDefs.append(PostfixLine('smtp', 'postfix/smtp\[.*to=', self.onSMTP))
        self._lineDefs.append(PostfixLine('virtual', 'postfix/virtual.*to=', self.onVirtual))
    
    def processFile(self, filePath):
        file = open(filePath, 'r')
        for line in file:
            for lineDef in self._lineDefs:
                if lineDef.match(line):
                    lineDef._handler(line)
        file.close()
    
    def processLines(self, lines):
        for line in lines:
            for lineDef in self._lineDefs:
                if lineDef.match(line):
                    lineDef._handler(line)
    
    def getInside(self, ss, left, right):
        p1 = ss.find(left)
        p2 = ss.find(right)
        return ss[p1 + 1:p2]
    
    def getInsideTuple(self, ss, left, right):
        p1 = ss.find(left)
        p2 = ss.find(right)
        return (ss[:p1],ss[p1 + 1:p2])
    
    def onStart(self, line):
        ss = line.split()
        pid = self.getInside(ss[4], '[', ']')
        (ptr, ip) = self.getInsideTuple(ss[7], '[', ']')
        date = "%s %s %s" % (ss[0], ss[1], ss[2])
        self._pidSMTPDMap[pid] = PostfixTransaction(date, ptr, ip)
 
    def onNoQueue(self, line):
        ss = line.split(None, 7)
        pid = self.getInside(ss[4], '[', ']')
        if pid in self._pidSMTPDMap:
            transaction = self._pidSMTPDMap[pid]
            infoColon = ss[7].split(':', 1)
            posFrom = infoColon[1].find('from=')
            transaction._result = infoColon[1][:posFrom].strip()
            fromToInfo = infoColon[1][posFrom:].split()
            transaction._from = self.getInside(fromToInfo[0], '<', '>')
            transaction._to = self.getInside(fromToInfo[1], '<', '>')
            transaction._helo = self.getInside(fromToInfo[3], '<', '>')
            transaction._status = 'noqu'
            self.report(transaction)
        else:
            print('Warn: Process %s not found in onNoQueue' % pid)

    def onQueue(self, line):
        ss = line.split(None, 7)
        pid = self.getInside(ss[4], '[', ']')
        if pid in self._pidSMTPDMap:
            transaction = self._pidSMTPDMap[pid]
            transaction._postfixID = ss[5].rstrip(':')
            self._postfixIDMap[transaction._postfixID] = transaction
        else:
            print('Warn: Process %s not found in onQueue' % pid)

    def onCleanup(self, line):
        ss = line.split(None, 7)
        if ss[5] == 'table':
            return
        postfixID = ss[5].rstrip(':')
        posEqual = ss[6].find('=')
        if posEqual > 0:
            messageID = ss[6][posEqual + 1:]
            if messageID[0] == '<':
                messageID = self.getInside(messageID, '<', '>')
            if postfixID in self._postfixIDMap:
                transaction = self._postfixIDMap[postfixID]
                transaction._messageID = messageID
                self._messageIDMap[messageID] = transaction
            elif messageID in self._messageIDMap:
                transaction = self._messageIDMap[messageID]
                transaction._postfixIDDelivery = postfixID
                self._postfixIDMap[postfixID] = transaction
        else:
            if ss[6] != 'discard:' and ss[6] != 'warning:':
                print("Error: Malformed messageID in onCleanup '%s'" % ss[6])
    
    def onQueued(self, line):
        ss = line.split(None, 6)
        postfixID = ss[5].rstrip(':')
        if postfixID in self._postfixIDMap:
            transaction = self._postfixIDMap[postfixID]
            info = ss[6].split(',')
            transaction._from = self.getInside(info[0], '<', '>')
            transaction._size = info[1][6:]
        #else:
        #    () 'Error: Transaction %s not found in onQueued' % postfixID)

    def onPipe(self, line):
        ss = line.split(None, 6)
        postfixID = ss[5].rstrip(':')
        if postfixID in self._postfixIDMap:
            transaction = self._postfixIDMap[postfixID]
            info = ss[6].split(',')
            transaction._to = self.getInside(info[0], '<', '>')
            transaction._delay = info[3][7:]
            transaction._status = 'come'
        #else:
        #    print('Error: Transaction %s not found in onPipe' % postfixID)

    def onSpam(self, line):
        ss = line.split(None, 12)
        pidSpam = self.getInside(ss[4], '[', ']')
        if ss[5] == 'processing':
            messageID = self.getInside(ss[7], '<', '>')
            if messageID in self._messageIDMap:
                transaction = self._messageIDMap[messageID]
                self._pidSpamMap[pidSpam] = transaction
            else:
                print("Error: Malformed messageID <%s>" % (messageID))
        elif ss[5] == 'clean' or ss[5] == 'identified':
            transaction = self._pidSpamMap[pidSpam]
            score = self.getInside(ss[7], '(', ')')
            transaction._spamScore, transaction._spamLimit = score.split('/')
            transaction._spamDelay = ss[11]
        elif ss[5] == 'result:':
            transaction = self._pidSpamMap[pidSpam]
            transaction._spamReport = ss[9]
            if ss[6] == 'Y':
                transaction._status = 'spam'
    
    def onSMTP(self, line):
        ss = line.split(None, 6)
        postfixID = ss[5].rstrip(':')
        if postfixID in self._postfixIDMap:
            transaction = self._postfixIDMap[postfixID]
            info = ss[6].split(',')
            transaction._to = self.getInside(info[0], '<', '>')
            transaction._relay = info[1][7:]
            transaction._delay = info[2][7:]
            transaction._status = 'gone'
            transaction._result = info[3][8:]
            transaction._transport = 'smtp'
        else:
            print('Error: Transaction %s not found in onSMTP' % postfixID)
        
    def onVirtual(self, line):
        ss = line.split(None, 6)
        postfixID = ss[5].rstrip(':')
        if postfixID in self._postfixIDMap:
            transaction = self._postfixIDMap[postfixID]
            info = ss[6].split(',')
            transaction._to = self.getInside(info[0], '<', '>')
            transaction._relay = info[1][7:]
            transaction._delay = info[2][7:]
            transaction._status = 'gone'
            transaction._result = info[3][8:]
            transaction._transport = 'virtual'
        else:
            print('Error: Transaction %s not found in onVirtual' % postfixID)
        
    def onRemoved(self, line):
        ss = line.split(None, 6)
        postfixID = ss[5].rstrip(':')
        if postfixID in self._postfixIDMap:
            transaction = self._postfixIDMap[postfixID]
            if postfixID == transaction._postfixIDDelivery:
                # The final delivery
                self.report(transaction)
            elif transaction._status == 'spam':
                self.report(transaction)
            else:
                # print('Error: Transaction %s not final in onRemoved' % postfixID)
                self.report(transaction)
        else:
            print('Error: Transaction %s not found in onRemoved' % postfixID)
        
    def report(self, tt):
        if self._reporter != None:
            self._reporter(tt)

def summaryReport(tt):
    print("%s id:%s %s to:%s from:%s" % (tt._status, tt._postfixID, tt._transport, tt._to, tt._from))

def spamSummaryReport(tt):
    reason = "%s %s" % (tt._spamReport, tt._result)
    print("%s %s id:%s score:%s %s to:%s from:%s %s" % (tt._dateTime, tt._status, tt._postfixID, tt._spamScore, tt._transport, tt._to, tt._from, reason))

def detailReport(tt):
    print("%s id: %s to: %s from: %s" % (tt_.dateTime, tt._postfixID, tt._to, tt._from))
    print("  status: %s" % tt._status)
    print("  result: %s" % tt._result)
    print("  spam score: %s" % tt._spamScore)
    print("  spam delay: %s" % tt._spamDelay)
    print("  spam report: %s" % tt._spamReport)
    print("  host: %s" % tt._host)

def main(argv):
    filePath = '/var/log/mail.log'
    try:                                
        opts, args = getopt.getopt(argv, "hf:", ["help", "file="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    app = PostfixAnalyzer()
    app._reporter = summaryReport
    for opt, arg in opts:
        if opt in ('-f', '--file'):
            filePath = arg
        elif opt in ('-h', '--help'):
            usage()
            sys.exit()
        elif opt in ('-r', '--report'):
            if arg == 'spam':
                app._reporter = spamSummaryReport
            
            
            
    app.processFile(filePath)

if __name__ == '__main__':
    main(sys.argv[1:])
