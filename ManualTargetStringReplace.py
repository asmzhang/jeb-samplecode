#?description=Manually replace target byte-array string decryptor calls in the current JEB Java view
#?shortcut=
# -*- coding: utf-8 -*-
from __future__ import print_function

import json
import os
import re
import subprocess

from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core.units.code.java import (
  IJavaSourceUnit, IJavaCall, IJavaConstant, IJavaClass,
  IJavaField, IJavaMethod, IJavaNewArray, IJavaAssignment, IJavaIdentifier,
  IJavaArrayElt
)


TARGETS_JSON = os.path.join(
  os.path.dirname(os.path.abspath(__file__)),
  'decode', 'src', 'main', 'resources', 'decode_targets.json'
)

# Run mode switch:
# - 'method': only current method
# - 'class': current class
# - 'all': whole project
# - 'auto': method if caret is in a method, else class
DEFAULT_MODE = 'all'

PRINT_HITS = True
DIAG = True
USE_JAVA_HELPER = True
JAVA_HELPER_JAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'decode', 'build', 'libs', 'decode-1.0-SNAPSHOT.jar')
JAVA_HELPER_MODE = 'serve'

RE_METHOD = re.compile(r"^\.method\b.*?\s([^\s(]+\(.*)$")
RE_END_METHOD = re.compile(r"^\.end method\b")
RE_LABEL = re.compile(r"^\s*(:\S+)\s*$")
RE_INSN = re.compile(r"^\s*([a-z0-9\-\/]+)(?:\s+(.*))?$")
RE_TRAILING_TYPE = re.compile(r"\([^)]*\)\s*$")

try:
  string_types = (basestring,)
except NameError:
  string_types = (str,)


def load_target_method_sigs():
  with open(TARGETS_JSON, 'r') as f:
    data = json.load(f)
  out = []
  for item in data:
    sig = item.get('dexSig')
    if isinstance(sig, string_types) and sig:
      out.append(sig)
  return out


TARGET_METHOD_SIGS = load_target_method_sigs()


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
    self._decode_cache = {}
    self._java_helper_proc = None
    self._java_helper_stdio = None
    self._java_helper_mode = None
    try:
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
          self.jfactory = unit.getDecompiler().getHighLevelContext()
          self.cstbuilder = self.jfactory.getConstantFactory()
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
      self.jfactory = unit.getDecompiler().getHighLevelContext()
      self.cstbuilder = self.jfactory.getConstantFactory()

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
    finally:
      self._close_java_helper()

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
    self._byte_array_cache = {}
    self._const_int_cache = {}
    self._const_byte_cache = {}
    self._array_name_cache = {}
    count = 0
    i = 0
    while i < body.size():
      stm = body.get(i)
      if self._try_replace_noop_call_statement(body, i, stm):
        count += 1
        i += 1
        continue
      pending_assignments = []
      count += self._visit_element(body, stm, pending_assignments, [body, stm])
      for assignment in pending_assignments:
        self._apply_assignment(assignment)
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

  def _visit_element(self, parent, e, pending_assignments, chain):
    count = 0
    if isinstance(e, IJavaCall) and self._try_replace_call(chain, e):
      count += 1
    if isinstance(e, IJavaAssignment):
      pending_assignments.append(e)
    try:
      subs = e.getSubElements()
    except Exception:
      return count
    for sub in subs:
      if isinstance(sub, (IJavaClass, IJavaField, IJavaMethod)):
        continue
      count += self._visit_element(e, sub, pending_assignments, chain + [sub])
    return count

  def _try_replace_noop_call_statement(self, body, index, stm):
    call = self._extract_direct_call_statement(stm)
    if call is None:
      return False
    plain = self._decode_target_call(call)
    if plain is None:
      return False
    repl = self._create_noop_string_statement(plain)
    if repl is None:
      return False
    try:
      result = body.set(index, repl)
      if DIAG:
        print('[D] body.set(%d) => %r for %s' % (index, result, self._safe_type_name(stm)))
      return True
    except Exception as e:
      if DIAG:
        print('[D] body.set failed for %s: %s' % (self._safe_type_name(stm), e))
    try:
      result = body.replaceSubElement(stm, repl)
      if DIAG:
        print('[D] body.replaceSubElement => %r for %s' % (result, self._safe_type_name(stm)))
      return bool(result)
    except Exception as e:
      if DIAG:
        print('[D] body.replaceSubElement failed for %s: %s' % (self._safe_type_name(stm), e))
    try:
      subs = body.getSubElements()
      idx = self._find_sub_index(subs, stm)
      if idx is not None:
        result = subs.set(idx, repl)
        if DIAG:
          print('[D] body.getSubElements().set(%d) => %r for %s' % (idx, result, self._safe_type_name(stm)))
        return True
    except Exception as e:
      if DIAG:
        print('[D] body.getSubElements().set failed for %s: %s' % (self._safe_type_name(stm), e))
    return False

  def _extract_direct_call_statement(self, e):
    cur = e
    for depth in range(8):
      filtered = self._get_filtered_subs(cur)
      if filtered is None:
        return None
      if len(filtered) != 1:
        if DIAG:
          print('[D] skip statement with %d sub-elements: %s' % (len(filtered), self._safe_type_name(cur)))
        return None
      child = filtered[0]
      if isinstance(child, IJavaCall):
        if depth > 0 and DIAG:
          print('[D] unwrapped statement chain: %s -> %s' % (self._safe_type_name(e), self._safe_type_name(child)))
        return child
      if DIAG:
        print('[D] unwrap statement: %s -> %s' % (self._safe_type_name(cur), self._safe_type_name(child)))
      cur = child
    return None

  def _get_filtered_subs(self, e):
    try:
      subs = e.getSubElements()
    except Exception:
      return None
    if not subs:
      return []
    filtered = []
    try:
      size = subs.size()
      for i in range(size):
        sub = subs.get(i)
        if isinstance(sub, (IJavaClass, IJavaField, IJavaMethod)):
          continue
        filtered.append(sub)
      return filtered
    except Exception:
      try:
        for sub in subs:
          if isinstance(sub, (IJavaClass, IJavaField, IJavaMethod)):
            continue
          filtered.append(sub)
        return filtered
      except Exception:
        return None

  def _create_noop_string_statement(self, plain):
    try:
      m = self.jfactory.createMethodReference('Ljava/lang/String;-><init>(Ljava/lang/String;)V', False)
      t = self.jfactory.getTypeFactory().createType('Ljava/lang/String;')
      args = [self.cstbuilder.createString(plain)]
      return self.jfactory.createNew(t, m, args)
    except Exception:
      return None

  def _decode_target_call(self, call):
    sig = str(call.getMethod().getSignature())
    if sig not in TARGET_METHOD_SIGS:
      return None

    args = call.getArguments()
    if not args or len(args) != 2:
      return None

    a1 = self._extract_byte_array(args[0])
    a2 = self._extract_byte_array(args[1])
    if a1 is None or a2 is None:
      if DIAG:
        print('[D] skip non-literal args: %s' % sig)
      return None

    plain = self._decode_with_java(sig, a1, a2)
    if not isinstance(plain, string_types):
      print('[!] decode failed: %s' % sig)
      return None

    if PRINT_HITS:
      print('[+] %s => %r' % (sig, plain))
    return plain

  def _try_replace_call(self, chain, call):
    plain = self._decode_target_call(call)
    if plain is None:
      return False
    repl = self.cstbuilder.createString(plain)
    return self._replace_call_via_ancestors(chain, call, repl)

  def _replace_call_via_ancestors(self, chain, call, repl):
    if not chain:
      return False
    if DIAG:
      try:
        names = [self._safe_type_name(x) for x in chain]
        print('[D] call chain: %s' % ' -> '.join(names))
      except Exception:
        pass

    child = call
    for i in range(len(chain) - 2, -1, -1):
      parent = chain[i]
      if self._replace_child_on_parent(parent, child, repl):
        return True
      child = parent
    return False

  def _replace_child_on_parent(self, parent, child, repl):
    try:
      result = parent.replaceSubElement(child, repl)
      if DIAG:
        print('[D] replaceSubElement(%s <- %s) => %r' % (
          self._safe_type_name(parent),
          self._safe_type_name(child),
          result
        ))
      if result:
        return True
    except Exception as e:
      if DIAG:
        print('[D] replaceSubElement(%s <- %s) failed: %s' % (
          self._safe_type_name(parent),
          self._safe_type_name(child),
          e
        ))
    try:
      subs = parent.getSubElements()
      idx = self._find_sub_index(subs, child)
      if idx is None:
        if DIAG:
          print('[D] child not found in getSubElements(): %s <- %s' % (
            self._safe_type_name(parent),
            self._safe_type_name(child)
          ))
        return False
      result = subs.set(idx, repl)
      if DIAG:
        print('[D] getSubElements().set(%s[%d] <- %s) => %r' % (
          self._safe_type_name(parent),
          idx,
          self._safe_type_name(child),
          result
        ))
      return True
    except Exception as e:
      if DIAG:
        print('[D] getSubElements().set(%s <- %s) failed: %s' % (
          self._safe_type_name(parent),
          self._safe_type_name(child),
          e
        ))
      return False

  def _find_sub_index(self, subs, target):
    try:
      size = subs.size()
      for i in range(size):
        x = subs.get(i)
        if x is target or x == target:
          return i
    except Exception:
      pass
    return None

  def _safe_type_name(self, obj):
    try:
      return obj.getClass().getName()
    except Exception:
      try:
        return obj.__class__.__name__
      except Exception:
        return '<unknown>'

  def _decode_with_java(self, sig, a1, a2):
    cache_key = (sig, tuple(a1), tuple(a2))
    if cache_key in self._decode_cache:
      return self._decode_cache[cache_key]
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
      if JAVA_HELPER_MODE == 'serve':
        plain = self._decode_with_java_server(java_exe, sig, a1, a2)
        if isinstance(plain, string_types):
          self._decode_cache[cache_key] = plain
          return plain
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      out, err = p.communicate()
      if p.returncode != 0:
        if DIAG:
          print('[D] java helper failed: %s' % err)
        return None
      plain = self._parse_helper_output(out)
      if isinstance(plain, string_types):
        self._decode_cache[cache_key] = plain
      return plain
    except Exception as e:
      if DIAG:
        print('[D] java helper exception: %s' % e)
      return None

  def _decode_with_java_server(self, java_exe, sig, a1, a2):
    proc = self._ensure_java_helper_process(java_exe)
    if not proc:
      return None
    try:
      payload = '%s\t%s\t%s\n' % (
        sig,
        ','.join(str(int(x)) for x in a1),
        ','.join(str(int(x)) for x in a2),
      )
      proc.stdin.write(payload)
      proc.stdin.flush()
      line = proc.stdout.readline()
      if not line:
        err = proc.stderr.read()
        if DIAG and err:
          print('[D] java helper server closed: %s' % err)
        self._close_java_helper()
        return None
      return self._parse_helper_output(line)
    except Exception as e:
      if DIAG:
        print('[D] java helper server exception: %s' % e)
      self._close_java_helper()
      return None

  def _ensure_java_helper_process(self, java_exe):
    proc = self._java_helper_proc
    try:
      if proc and proc.poll() is None:
        return proc
    except Exception:
      pass
    self._close_java_helper()
    cmd = [java_exe, '-jar', JAVA_HELPER_JAR, 'serve']
    try:
      self._java_helper_proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
      )
      self._java_helper_mode = 'serve'
      return self._java_helper_proc
    except Exception as e:
      if DIAG:
        print('[D] start java helper server failed: %s' % e)
      self._close_java_helper()
      return None

  def _parse_helper_output(self, raw):
    if raw is None:
      return None
    try:
      text = raw.decode('utf-8').strip()
    except Exception:
      try:
        text = raw.strip()
      except Exception:
        return None
    if not text:
      return None
    try:
      obj = json.loads(text)
    except Exception:
      if DIAG:
        print('[D] invalid helper json: %r' % text)
      return None
    if obj.get('type') == 'Ljava/lang/String;':
      return obj.get('value')
    return None

  def _close_java_helper(self):
    proc = getattr(self, '_java_helper_proc', None)
    if not proc:
      return
    self._java_helper_proc = None
    try:
      if proc.stdin:
        proc.stdin.close()
    except Exception:
      pass
    try:
      if proc.stdout:
        proc.stdout.close()
    except Exception:
      pass
    try:
      if proc.stderr:
        proc.stderr.close()
    except Exception:
      pass
    try:
      if proc.poll() is None:
        proc.terminate()
    except Exception:
      pass

  def _extract_byte_array(self, e):
    cache_key = None
    try:
      if isinstance(e, IJavaIdentifier):
        v = self.locals.get(e.getName())
        if v is not None:
          return list(v)
    except Exception:
      pass
    try:
      cache_key = id(e)
      cached = self._byte_array_cache.get(cache_key)
      if cached is not None:
        return list(cached) if cached else None
    except Exception:
      cache_key = None

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
              if cache_key is not None:
                self._byte_array_cache[cache_key] = ()
              return None
            out.append(bv)
          result = out if out else None
          if cache_key is not None:
            self._byte_array_cache[cache_key] = tuple(result or ())
          return result
        try:
          s = str(e)
          m = re.search(r'new\s+byte\s*\[\s*([^\]]+)\s*\]', s)
          if m:
            n = parse_int(m.group(1))
            if n >= 0:
              result = [0] * n
              if cache_key is not None:
                self._byte_array_cache[cache_key] = tuple(result)
              return result
        except Exception:
          pass
    except Exception:
      pass

    try:
      if hasattr(e, 'getElementType') and str(e.getElementType()) == 'byte':
        out = []
        for x in e.getSubElements():
          if not isinstance(x, IJavaConstant):
            if cache_key is not None:
              self._byte_array_cache[cache_key] = ()
            return None
          v = parse_byte_literal(x.getValue())
          if v is None:
            if cache_key is not None:
              self._byte_array_cache[cache_key] = ()
            return None
          out.append(v)
        result = out if out else None
        if cache_key is not None:
          self._byte_array_cache[cache_key] = tuple(result or ())
        return result
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
          if cache_key is not None:
            self._byte_array_cache[cache_key] = tuple(out)
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
            if cache_key is not None:
              self._byte_array_cache[cache_key] = ()
            return None
          out.append(v)
        result = out if out else None
        if cache_key is not None:
          self._byte_array_cache[cache_key] = tuple(result or ())
        return result
    except Exception:
      pass

    if cache_key is not None:
      self._byte_array_cache[cache_key] = ()
    return None

  def _apply_assignment(self, e):
    try:
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

  def _get_array_name(self, e):
    try:
      cache_key = id(e)
      if cache_key in self._array_name_cache:
        return self._array_name_cache[cache_key]
    except Exception:
      cache_key = None
    try:
      if isinstance(e, IJavaIdentifier):
        name = e.getName()
        if cache_key is not None:
          self._array_name_cache[cache_key] = name
        return name
    except Exception:
      pass
    try:
      for sub in e.getSubElements():
        name = self._get_array_name(sub)
        if name is not None:
          if cache_key is not None:
            self._array_name_cache[cache_key] = name
          return name
    except Exception:
      pass
    if cache_key is not None:
      self._array_name_cache[cache_key] = None
    return None

  def _get_const_int(self, e):
    try:
      cache_key = id(e)
      if cache_key in self._const_int_cache:
        return self._const_int_cache[cache_key]
    except Exception:
      cache_key = None
    try:
      if isinstance(e, IJavaConstant):
        if hasattr(e, 'getInt'):
          value = int(e.getInt())
          if cache_key is not None:
            self._const_int_cache[cache_key] = value
          return value
        value = parse_int(e.getValue())
        if cache_key is not None:
          self._const_int_cache[cache_key] = value
        return value
    except Exception:
      pass
    try:
      value = parse_int(str(e))
      if cache_key is not None:
        self._const_int_cache[cache_key] = value
      return value
    except Exception:
      if cache_key is not None:
        self._const_int_cache[cache_key] = None
      return None

  def _get_const_byte(self, e):
    try:
      cache_key = id(e)
      if cache_key in self._const_byte_cache:
        return self._const_byte_cache[cache_key]
    except Exception:
      cache_key = None
    try:
      v = parse_byte_literal(str(e))
      if v is not None:
        if cache_key is not None:
          self._const_byte_cache[cache_key] = v
        return v
    except Exception:
      pass
    try:
      if isinstance(e, IJavaConstant):
        if hasattr(e, 'getValue'):
          v = parse_byte_literal(e.getValue())
          if v is not None:
            if cache_key is not None:
              self._const_byte_cache[cache_key] = v
            return v
        if hasattr(e, 'getByte'):
          v = parse_byte_literal(e.getByte())
          if cache_key is not None:
            self._const_byte_cache[cache_key] = v
          return v
        if hasattr(e, 'getInt'):
          v = parse_byte_literal(e.getInt())
          if cache_key is not None:
            self._const_byte_cache[cache_key] = v
          return v
    except Exception:
      pass
    if cache_key is not None:
      self._const_byte_cache[cache_key] = None
    return None
