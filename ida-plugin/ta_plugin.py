import idaapi, idc
import subprocess
from enum import IntEnum

CONF_PIN_PATH =  "~/Workspace/pin-2.14/"

class RegParts(IntEnum):
    LOW = 0,
    HIGH = 1,
    WORD = 2,
    DWORD = 4,
    QWORD = 8,
    OWORD = 16,
    YWORD = 32,


class Registers(IntEnum):
    RAX = 0,
    RBX = 1,
    RCX = 2,
    RDX = 3,
    RDI = 4,
    RSI = 5,
    RBP = 6,
    RSP = 7,
    RIP = 8,
    R8 = 9,
    R9 = 10,
    R10 = 11,
    R11 = 12,
    R12 = 13,
    R13 = 14,
    R14 = 15,
    R15 = 16,
    XMM0 = 17,
    XMM1 = 18,
    XMM2 = 19,
    XMM3 = 20,
    XMM4 = 21,
    XMM5 = 22,
    XMM6 = 23,
    XMM7 = 24,
    XMM8 = 25,
    XMM9 = 26,
    XMM10 = 27,
    XMM11 = 28,
    XMM12 = 29,
    XMM13 = 30,
    XMM14 = 31,
    XMM15 = 32,
    RFLAGS = 33,
    YMM0 = 34,
    YMM1 = 35,
    YMM2 = 36,
    YMM3 = 37,
    YMM4 = 38,
    YMM5 = 39,
    YMM6 = 40,
    YMM7 = 41,
    YMM8 = 42,
    YMM9 = 43,
    YMM10 = 44,
    YMM11 = 45,
    YMM12 = 46,
    YMM13 = 47,
    YMM14 = 48,
    QueueYMM15 = 49,


class Flags(IntEnum):
    AF = 0,
    CF = 1,
    DF = 2,
    IF = 3,
    OF = 4,
    PF = 5,
    SF = 6,
    TF = 7,
    ZF = 8,


class TaintAll(object):
    """TaintAll"""

    PIN_PATH = CONF_PIN_PATH + "/pin"
    TA_PATH = CONF_PIN_PATH + "/source/tools/TaintAll/obj-intel64/main.dylib"
    TARGET_FILE = None
    TARGET_PATH = None
    RESULT_FILE = "results.ta"
    COLOR_TAINTED = 0x00A5EE
    COLOR_CLEAR = 0xFFFFFF

    def __init__(self):
        self.__tpargs = ""
        self.__trargs = ""
        self.__taargs = ""
        self.__sffargs = ""
        self.__sfrargs = ""
        self.__taintStart = None
        self.__taintStop = None
        self.TARGET_FILE = idaapi.get_root_filename()
        self.TARGET_PATH = idaapi.get_input_file_path()[:-len(self.TARGET_FILE)]
        self.__programArguments = []

        self.__taintedRegs = []
        self.__taintedMems = []
        self.__taintedAddrs = []
        self.__solutions = []
        self.__chains = []

    def start(self):
        """
        print ("PIN_PATH: {0}".format(self.PIN_PATH))
        print("TA_PATH: {0}".format(self.TA_PATH))
        print ("TARGET_FILE: {0}".format(self.TARGET_FILE))
        print ("TARGET_PATH: {0}".format(self.TARGET_PATH))
        """
        pass

    def taintPointer(self, insaddr, reg, size):
        tmp = "0x{0:x},{1},{2}".format(insaddr, reg, size)
        self.__tpargs = self.__concatArgs(self.__tpargs, tmp)

    def taintRegister(self, insaddr, reg, regpart):
        tmp = "0x{0:x},{1},{2}".format(insaddr, reg, regpart)
        self.__trargs = self.__concatArgs(self.__trargs, tmp)

    def taintAddress(self, insaddr, memaddr, size):
        tmp = "0x{0:x},{1},{2}".format(insaddr, memaddr, size)
        self.__taargs = self.__concatArgs(self.__taargs, tmp)

    def __concatArgs(self, old, new):
        if len(old) > 1:
            return "{0},{1}".format(old, new)
        else:
            return new

    def startTaintAt(self, addr):
        self.__taintStart = addr

    def stopTaintAt(self, addr):
        self.__taintStop = addr

    def prepCMDLine(self):
        cmd = [
            self.PIN_PATH,
            '-t',
            self.TA_PATH,
            '-sib',
            "0x{0:x}".format(idaapi.get_imagebase()),
            "-bt",
            "0x{0:x}".format(self.__taintStart),
            "-et",
            "0x{0:x}".format(self.__taintStop)]

        if len(self.__tpargs) > 1:
            cmd.append("-tp")
            cmd.append(self.__tpargs)

        if len(self.__trargs) > 1:
            cmd.append("-tr")
            cmd.append(self.__trargs)

        if len(self.__taargs) > 1:
            cmd.append("-ta")
            cmd.append(self.__taargs)

        if len(self.__sffargs) > 1:
            cmd.append("-sff")
            cmd.append(self.__sffargs)

        if len(self.__sfrargs) > 1:
            cmd.append("-sfr")
            cmd.append(self.__sfrargs)

        cmd.append("--")
        cmd.append(self.TARGET_PATH + self.TARGET_FILE)

        return cmd + self.__programArguments

    def startDynamicAnalysis(self):
        print("Starting dynamic analysis!")

        subprocess.check_call(
            self.prepCMDLine(),
            cwd=self.TARGET_PATH)

        with open(self.TARGET_PATH + self.RESULT_FILE, "r") as f:
            for l in f.readlines():
                line = l[:-1].split(',')
                if line[0] == 'T':
                    regs = line[2].split(':')[1:-1]
                    mems = line[3].split(':')[1:-1]
                    self.__taintedRegs.append((int(line[1], 16), regs))
                    self.__taintedMems.append((int(line[1], 16), mems))
                    self.__taintedAddrs.append(int(line[1], 16))
                    idc.SetColor(int(line[1], 16), 1, self.COLOR_TAINTED)
                elif line[0] == 'R':
                    self.__solutions.append((
                        int(line[1], 16),
                        int(line[2], 16),
                        line[3]))

        if self.__taintedAddrs:
            idc.Jump(self.__taintedAddrs[0])
            print("Done!")
        else:
            print("There aren't any affected addresses.")

    def printRegsEA(self):
        ea = idc.ScreenEA()

        for line in self.__taintedRegs:
            if line[0] == ea:
                print(line[1])
                break

    def printMemsEA(self):
        ea = idc.ScreenEA()

        for line in self.__taintedMems:
            if line[0] == ea:
                print(line[1])
                break

    def printAffectedAddrs(self):
        for line in self.__taintedAddrs:
            print(hex(line))

    def addProgramArguments(self, args):
        self.__programArguments = args

    def hideTaints(self):
        for insaddr in self.__taintedAddrs:
            idc.SetColor(insaddr, 1, self.COLOR_CLEAR)

    def showTaints(self):
        for insaddr in self.__taintedAddrs:
            idc.SetColor(insaddr, 1, self.COLOR_TAINTED)


class ta_plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "TaintAll IDA Plugin"
    help = "Somebody call 911"
    wanted_name = "TaintAll"
    wanted_hotkey = ""

    def init(self):
        self.ida_msg("Initializing")
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        self.a = TaintAll()
        self.a.start()

    def term(self):
        self.ida_msg("Terminating")

    def ida_msg(self, msg):
        idaapi.msg("[TA] {0}\n".format(msg))


def PLUGIN_ENTRY():
    return ta_plugin()
