#?description=Manually replace target byte-array string decryptor calls in the current JEB Java view
#?shortcut=
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import re
import json
import subprocess

from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core.units.code.java import (
  IJavaSourceUnit, IJavaCall, IJavaConstant, IJavaClass,
  IJavaField, IJavaMethod, IJavaNewArray, IJavaAssignment, IJavaIdentifier,
  IJavaArrayElt
)


TARGET_METHOD_SIGS = [
  "Lcom/mbridge/msdk/shell/MBService;->oOoooOoooOOOooo([B[B)Ljava/lang/String;",
  "Li1iIiI1iIiIiIiiI1iI;->oOoooOoooOOOooo([B[B)Ljava/lang/String;",
]

# Run mode switch:
# - 'method': only current method
# - 'class': current class
# - 'all': whole project
# - 'auto': method if caret is in a method, else class
DEFAULT_MODE = 'all'

PRINT_HITS = True
DIAG = False
USE_JAVA_HELPER = True
JAVA_HELPER_JAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'decode', 'build', 'libs', 'decode-1.0-SNAPSHOT.jar')

RE_METHOD = re.compile(r"^\.method\b.*?\s([^\s(]+\(.*)$")
RE_END_METHOD = re.compile(r"^\.end method\b")
RE_LABEL = re.compile(r"^\s*(:\S+)\s*$")
RE_INSN = re.compile(r"^\s*([a-z0-9\-\/]+)(?:\s+(.*))?$")
RE_TRAILING_TYPE = re.compile(r"\([^)]*\)\s*$")

try:
  string_types = (basestring,)
except NameError:
  string_types = (str,)


def parse_int(v):
  s = str(v).strip()
  s = RE_TRAILING_TYPE.sub('', s).strip()
  s = s.rstrip('Ll')
  neg = False
  if s.startswith('-'):
    neg = True
    s = s[1:]
  if s.startswith('0x') or s.startswith('0X'):
    n = int(s, 16)
  else:
    n = int(s, 10)
  return -n if neg else n


def to_byte(v):
  return ((int(v) + 128) % 256) - 128


def classsig_to_relpath(class_sig):
  return class_sig[1:-1].replace('/', os.sep) + '.smali'


def sig_to_classsig(method_sig):
  p = method_sig.find('->')
  return method_sig[:p]


def dotted_name(class_sig):
  return class_sig[1:-1].replace('/', '.')


def parse_byte_literal(v):
  try:
    return to_byte(parse_int(v))
  except Exception:
    return None


def discover_decode_roots():
  roots = []
  bases = []
  try:
    bases.append(os.path.dirname(os.path.abspath(__file__)))
  except Exception:
    pass
  try:
    bases.append(os.getcwd())
  except Exception:
    pass
  extra = []
  for b in bases:
    extra.append(b)
    extra.append(os.path.dirname(b))
  seen = set()
  for base in extra:
    if not base or base in seen or not os.path.isdir(base):
      continue
    seen.add(base)
    for name in os.listdir(base):
      p = os.path.join(base, name)
      if not os.path.isdir(p):
        continue
      try:
        if any(x.startswith('smali') for x in os.listdir(p)):
          roots.append(p)
      except Exception:
        pass
  return roots


class SmaliMethod(object):
  def __init__(self, class_sig, signature, body_lines):
    self.class_sig = class_sig
    self.signature = signature
    self.instructions = []
    self.labels = {}
    self._parse(body_lines)

  def _parse(self, lines):
    for raw in lines:
      line = raw.strip()
      if not line or line.startswith('#') or line.startswith('.'):
        m = RE_LABEL.match(line)
        if m:
          self.labels[m.group(1)] = len(self.instructions)
        continue
      m = RE_LABEL.match(line)
      if m:
        self.labels[m.group(1)] = len(self.instructions)
        continue
      m = RE_INSN.match(line)
      if not m:
        continue
      self.instructions.append((m.group(1), m.group(2) or ''))


class SmaliRepository(object):
  def __init__(self, roots):
    self.roots = roots
    self.class_cache = {}
    self.method_cache = {}
    self.unsupported = set()

  def get_method(self, method_sig):
    if method_sig in self.method_cache:
      return self.method_cache[method_sig]
    if method_sig in self.unsupported:
      return None
    class_sig = sig_to_classsig(method_sig)
    methods = self._load_class(class_sig)
    if not methods:
      self.unsupported.add(method_sig)
      return None
    m = methods.get(method_sig)
    if not m:
      self.unsupported.add(method_sig)
      return None
    self.method_cache[method_sig] = m
    return m

  def _load_class(self, class_sig):
    if class_sig in self.class_cache:
      return self.class_cache[class_sig]
    rel = classsig_to_relpath(class_sig)
    fp = None
    for root in self.roots:
      for name in os.listdir(root):
        if not name.startswith('smali'):
          continue
        candidate = os.path.join(root, name, rel)
        if os.path.isfile(candidate):
          fp = candidate
          break
      if fp:
        break
    if not fp:
      self.class_cache[class_sig] = None
      return None

    methods = {}
    with open(fp, 'r') as f:
      lines = f.readlines()
    in_method = False
    cur = []
    cur_sig = None
    for raw in lines:
      line = raw.rstrip('\r\n')
      if not in_method:
        m = RE_METHOD.match(line.strip())
        if m:
          cur_sig = class_sig + '->' + m.group(1)
          cur = []
          in_method = True
        continue
      if RE_END_METHOD.match(line.strip()):
        methods[cur_sig] = SmaliMethod(class_sig, cur_sig, cur)
        in_method = False
        cur_sig = None
        cur = []
        continue
      cur.append(line)

    self.class_cache[class_sig] = methods
    return methods


class SmaliEvaluator(object):
  def __init__(self, repo):
    self.repo = repo
    self.depth = 0

  def evaluate(self, method_sig, args):
    method = self.repo.get_method(method_sig)
    if not method or self.depth > 8:
      return None
    self.depth += 1
    try:
      return self._execute(method, args)
    finally:
      self.depth -= 1

  def _execute(self, method, args):
    regs = {}
    last_result = None
    for i, arg in enumerate(args):
      regs['p%d' % i] = [to_byte(x) for x in arg] if isinstance(arg, list) else arg

    pc = 0
    insns = method.instructions
    labels = method.labels

    while pc < len(insns):
      op, rest = insns[pc]

      if op.startswith('const/'):
        dst, value = [x.strip() for x in rest.split(',', 1)]
        regs[dst] = parse_int(value)
        pc += 1
        continue

      if op == 'const-class':
        dst, value = [x.strip() for x in rest.split(',', 1)]
        regs[dst] = {'kind': 'class', 'sig': value}
        pc += 1
        continue

      if op in ('move', 'move-object'):
        dst, src = [x.strip() for x in rest.split(',', 1)]
        value = regs.get(src)
        regs[dst] = list(value) if isinstance(value, list) else value
        pc += 1
        continue

      if op in ('move-result', 'move-result-object'):
        regs[rest.strip()] = last_result
        pc += 1
        continue

      if op == 'new-instance':
        dst, typ = [x.strip() for x in rest.split(',', 1)]
        regs[dst] = {'kind': 'new', 'type': typ, 'value': None}
        pc += 1
        continue

      if op == 'sget-object':
        dst, field_sig = [x.strip() for x in rest.split(',', 1)]
        if field_sig.startswith('Ljava/nio/charset/StandardCharsets;->UTF_8:'):
          regs[dst] = 'utf-8'
        else:
          return None
        pc += 1
        continue

      if op == 'array-length':
        dst, src = [x.strip() for x in rest.split(',', 1)]
        regs[dst] = len(regs.get(src) or [])
        pc += 1
        continue

      if op == 'aget-byte':
        dst, arr, idx = [x.strip() for x in rest.split(',', 2)]
        regs[dst] = to_byte(regs[arr][regs[idx]])
        pc += 1
        continue

      if op == 'aput-byte':
        src, arr, idx = [x.strip() for x in rest.split(',', 2)]
        regs[arr][regs[idx]] = to_byte(regs[src])
        pc += 1
        continue

      if op in ('xor-int/2addr', 'add-int/2addr', 'sub-int/2addr'):
        dst, src = [x.strip() for x in rest.split(',', 1)]
        a = int(regs[dst])
        b = int(regs[src])
        regs[dst] = a ^ b if op == 'xor-int/2addr' else (a + b if op == 'add-int/2addr' else a - b)
        pc += 1
        continue

      if op == 'add-int/lit8':
        dst, src, lit = [x.strip() for x in rest.split(',', 2)]
        regs[dst] = int(regs[src]) + parse_int(lit)
        pc += 1
        continue

      if op == 'int-to-byte':
        dst, src = [x.strip() for x in rest.split(',', 1)]
        regs[dst] = to_byte(regs[src])
        pc += 1
        continue

      if op in ('if-ge', 'if-lt'):
        left, right, label = [x.strip() for x in rest.split(',', 2)]
        a = int(regs[left])
        b = int(regs[right])
        pc = labels[label] if ((a >= b) if op == 'if-ge' else (a < b)) else pc + 1
        continue

      if op == 'goto':
        pc = labels[rest.strip()]
        continue

      if op in ('invoke-static', 'invoke-virtual', 'invoke-direct'):
        regs_part, target = rest.split('},', 1)
        target = target.strip()
        arg_regs = regs_part.strip()[1:].strip()
        arg_regs = [x.strip() for x in arg_regs.split(',') if x.strip()]
        values = [regs.get(r) for r in arg_regs]

        if op == 'invoke-static':
          copied = [list(v) if isinstance(v, list) else v for v in values]
          last_result = self.evaluate(target, copied)
          if target.endswith(')[B') and isinstance(last_result, list) and arg_regs:
            regs[arg_regs[0]] = last_result
        elif op == 'invoke-virtual':
          last_result = self._invoke_virtual(target, values)
        else:
          last_result = self._invoke_direct(target, values)

        if last_result is None and target.startswith('Ljava/lang/String;-><init>('):
          last_result = values[0]
        pc += 1
        continue

      if op == 'return-object':
        return regs.get(rest.strip())

      if op == 'return-void':
        return None

      return None

    return None

  def _invoke_virtual(self, target, values):
    if target == 'Ljava/lang/Class;->toString()Ljava/lang/String;':
      obj = values[0]
      if isinstance(obj, dict) and obj.get('kind') == 'class':
        return 'class ' + dotted_name(obj['sig'])
    if target == 'Ljava/lang/String;->length()I':
      return len(values[0])
    return None

  def _invoke_direct(self, target, values):
    if target == 'Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V':
      obj, arr, charset = values
      charset = charset or 'utf-8'
      obj['value'] = bytearray((x & 0xFF) for x in arr).decode(charset)
      return obj
    return None


class ManualTargetStringReplace(IScript):
  def run(self, ctx):
    argv = []
    try:
      argv = list(ctx.getArguments() or [])
    except Exception:
      argv = []
    mode = DEFAULT_MODE
    for x in argv:
      if x in ('method', '--method', '-m'):
        mode = 'method'
      elif x in ('class', '--class', '-c'):
        mode = 'class'
      elif x in ('all', '--all', '-a'):
        mode = 'all'

    print('[*] Mode: %s' % mode)

    if not isinstance(ctx, IGraphicalClientContext):
      print('[!] GUI context required')
      return

    f = ctx.getFocusedFragment()
    if not f and mode != 'all':
      print('[!] No focused fragment')
      return

    self.repo = SmaliRepository(discover_decode_roots())
    self.eval = SmaliEvaluator(self.repo)
    self.replcnt = 0
    self._changed_units = set()

    if mode == 'all':
      prj = ctx.getMainProject()
      if not prj:
        print('[!] No project')
        return
      total_units = 0
      for unit in prj.findUnits(IJavaSourceUnit):
        try:
          root = unit.getASTElement()
        except Exception:
          root = None
        if not isinstance(root, IJavaClass):
          continue
        total_units += 1
        self.cstbuilder = unit.getDecompiler().getHighLevelContext().getConstantFactory()
        n = self._process_class(root)
        if n:
          self.replcnt += n
          unit.notifyGenericChange()
      print('[*] Processed %d Java units' % total_units)
      print('[*] Replaced %d calls' % self.replcnt)
      return

    unit = f.getUnit()
    if not isinstance(unit, IJavaSourceUnit):
      print('[!] Focus a decompiled Java unit first')
      return
    root = unit.getASTElement()
    if not isinstance(root, IJavaClass):
      print('[!] Focus a Java class first')
      return
    self.cstbuilder = unit.getDecompiler().getHighLevelContext().getConstantFactory()

    focused_method = self._get_focused_method(f)
    if mode == 'method':
      if not focused_method:
        print('[!] Mode=method requires caret inside a Java method')
        return
      print('[*] Focused method: %s' % focused_method.getSignature())
      self.replcnt += self._process_method(focused_method)
    elif mode == 'class':
      self.replcnt += self._process_class(root)
    elif focused_method:
      print('[*] Focused method: %s' % focused_method.getSignature())
      self.replcnt += self._process_method(focused_method)
    else:
      self.replcnt += self._process_class(root)

    if self.replcnt:
      unit.notifyGenericChange()
    print('[*] Replaced %d calls' % self.replcnt)

  def _get_focused_method(self, frag):
    try:
      astobjstk = frag.getDocumentObjectsAtCaret()
    except Exception:
      astobjstk = None
    if not astobjstk:
      return None
    for obj in reversed(astobjstk):
      if isinstance(obj, IJavaMethod):
        return obj
    return None

  def _process_method(self, method):
    try:
      body = method.getBody()
    except Exception:
      body = None
    if body is None:
      return 0
    self.locals = {}
    count = 0
    i = 0
    while i < body.size():
      stm = body.get(i)
      count += self._check_element(body, stm)
      self._collect_assignments(stm)
      i += 1
    return count

  def _process_class(self, javaClass):
    count = 0
    for m in javaClass.getMethods():
      count += self._process_method(m)
    for sub in javaClass.getSubElements():
      if isinstance(sub, IJavaClass):
        count += self._process_class(sub)
    return count

  def _check_element(self, parent, e):
    count = 0
    if isinstance(e, IJavaCall) and self._try_replace_call(parent, e):
      return 1
    for sub in e.getSubElements():
      if isinstance(sub, (IJavaClass, IJavaField, IJavaMethod)):
        continue
      count += self._check_element(e, sub)
    return count

  def _try_replace_call(self, parent, call):
    sig = str(call.getMethod().getSignature())
    if sig not in TARGET_METHOD_SIGS:
      return False

    args = call.getArguments()
    if not args or len(args) != 2:
      return False

    a1 = self._extract_byte_array(args[0])
    a2 = self._extract_byte_array(args[1])
    if a1 is None or a2 is None:
      if DIAG:
        print('[D] skip non-literal args: %s' % sig)
      return False

    plain = self._decode_with_java(sig, a1, a2)
    if not isinstance(plain, string_types):
      print('[!] decode failed: %s' % sig)
      return False

    if PRINT_HITS:
      print('[+] %s => %r' % (sig, plain))

    parent.replaceSubElement(call, self.cstbuilder.createString(plain))
    return True

  def _decode_with_java(self, sig, a1, a2):
    if not USE_JAVA_HELPER:
      return None
    if not os.path.isfile(JAVA_HELPER_JAR):
      return None
    java_home = os.environ.get('JAVA_HOME')
    if not java_home:
      return None
    java_exe = os.path.join(java_home, 'bin', 'java.exe')
    if not os.path.isfile(java_exe):
      return None

    cmd = [
      java_exe,
      '-jar',
      JAVA_HELPER_JAR,
      'invoke',
      '--target',
      sig,
      '--arg',
      ','.join(str(int(x)) for x in a1),
      '--arg',
      ','.join(str(int(x)) for x in a2),
    ]
    try:
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      out, err = p.communicate()
      if p.returncode != 0:
        if DIAG:
          print('[D] java helper failed: %s' % err)
        return None
      text = out.decode('utf-8').strip()
      if not text:
        return None
      obj = json.loads(text)
      if obj.get('type') == 'Ljava/lang/String;':
        return obj.get('value')
      return None
    except Exception as e:
      if DIAG:
        print('[D] java helper exception: %s' % e)
      return None

  def _extract_byte_array(self, e):
    try:
      if isinstance(e, IJavaIdentifier):
        v = self.locals.get(e.getName())
        if v is not None:
          return list(v)
    except Exception:
      pass

    try:
      if isinstance(e, IJavaNewArray):
        vals = e.getInitialValues()
        if vals:
          out = []
          for v in vals:
            if not isinstance(v, IJavaConstant):
              return None
            bv = parse_byte_literal(v.getValue())
            if bv is None:
              return None
            out.append(bv)
          return out if out else None
        try:
          s = str(e)
          m = re.search(r'new\s+byte\s*\[\s*([^\]]+)\s*\]', s)
          if m:
            n = parse_int(m.group(1))
            if n >= 0:
              return [0] * n
        except Exception:
          pass
    except Exception:
      pass

    try:
      if hasattr(e, 'getElementType') and str(e.getElementType()) == 'byte':
        out = []
        for x in e.getSubElements():
          if not isinstance(x, IJavaConstant):
            return None
          v = parse_byte_literal(x.getValue())
          if v is None:
            return None
          out.append(v)
        return out if out else None
    except Exception:
      pass

    try:
      subs = e.getSubElements()
      if subs and subs.size() > 0:
        out = []
        ok = True
        for i in range(subs.size()):
          x = subs.get(i)
          v = self._get_const_byte(x)
          if v is None:
            ok = False
            break
          out.append(v)
        if ok and out:
          return out
    except Exception:
      pass

    try:
      s = str(e)
      bo = s.find('{')
      bc = s.rfind('}')
      if 'new byte[]' in s and bo != -1 and bc != -1:
        parts = [p.strip() for p in s[bo + 1:bc].split(',') if p.strip()]
        out = []
        for p in parts:
          v = parse_byte_literal(p)
          if v is None:
            return None
          out.append(v)
        return out if out else None
    except Exception:
      pass

    return None

  def _collect_assignments(self, e):
    try:
      if isinstance(e, IJavaAssignment):
        left = e.getLeft()
        right = e.getRight()
        if isinstance(left, IJavaIdentifier):
          arr = self._extract_byte_array(right)
          if arr is not None:
            self.locals[left.getName()] = list(arr)
        elif isinstance(left, IJavaArrayElt):
          arr_name = self._get_array_name(left.getArray())
          idx = self._get_const_int(left.getIndex())
          val = self._get_const_byte(right)
          if arr_name is not None and idx is not None and val is not None:
            arr = self.locals.get(arr_name)
            if arr is not None and 0 <= idx < len(arr):
              arr[idx] = val
    except Exception:
      pass

    try:
      subs = e.getSubElements()
    except Exception:
      return
    for sub in subs:
      if isinstance(sub, (IJavaClass, IJavaField, IJavaMethod)):
        continue
      self._collect_assignments(sub)

  def _get_array_name(self, e):
    try:
      if isinstance(e, IJavaIdentifier):
        return e.getName()
    except Exception:
      pass
    try:
      for sub in e.getSubElements():
        name = self._get_array_name(sub)
        if name is not None:
          return name
    except Exception:
      pass
    return None

  def _get_const_int(self, e):
    try:
      if isinstance(e, IJavaConstant):
        if hasattr(e, 'getInt'):
          return int(e.getInt())
        return parse_int(e.getValue())
    except Exception:
      pass
    try:
      return parse_int(str(e))
    except Exception:
      return None

  def _get_const_byte(self, e):
    try:
      v = parse_byte_literal(str(e))
      if v is not None:
        return v
    except Exception:
      pass
    try:
      if isinstance(e, IJavaConstant):
        if hasattr(e, 'getValue'):
          v = parse_byte_literal(e.getValue())
          if v is not None:
            return v
        if hasattr(e, 'getByte'):
          return parse_byte_literal(e.getByte())
        if hasattr(e, 'getInt'):
          return parse_byte_literal(e.getInt())
    except Exception:
      pass
    return None
