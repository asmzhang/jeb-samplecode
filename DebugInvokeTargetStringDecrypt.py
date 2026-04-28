#?description=Debug target decryptor on the currently focused Java method/class
#?shortcut=
from __future__ import print_function

import json
import os

from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaClass, IJavaMethod, IJavaCall

TARGETS_JSON = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'decode', 'src', 'main', 'resources', 'decode_targets.json'
)

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


class DebugInvokeTargetStringDecrypt(IScript):
  def run(self, ctx):
    if not isinstance(ctx, IGraphicalClientContext):
      print('[!] GUI context required')
      return

    frag = ctx.getFocusedFragment()
    if not frag:
      print('[!] No focused fragment')
      return

    unit = frag.getUnit()
    if not isinstance(unit, IJavaSourceUnit):
      print('[!] Focus a decompiled Java view first')
      return

    root = unit.getASTElement()
    if not isinstance(root, IJavaClass):
      print('[!] Focus a Java class first')
      return

    print('[*] target method signatures:')
    for sig in TARGET_METHOD_SIGS:
      print('    %s' % sig)

    print('[*] focused unit: %s' % unit)

    astobjstk = None
    try:
      astobjstk = frag.getDocumentObjectsAtCaret()
    except Exception:
      astobjstk = None

    focused_method = None
    if astobjstk:
      for obj in reversed(astobjstk):
        if isinstance(obj, IJavaMethod):
          focused_method = obj
          break

    if focused_method:
      print('[*] focused method: %s' % focused_method.getSignature())
      body = focused_method.getBody()
      if body is None:
        print('[!] Focused method has no body')
        return
      self._scan_method(body)
      return

    print('[*] no focused method at caret, scanning methods of current class only')
    for m in root.getMethods():
      body = m.getBody()
      if body is None:
        continue
      print('[*] method: %s' % m.getSignature())
      self._scan_method(body)

  def _scan_method(self, e):
    if isinstance(e, IJavaCall):
      try:
        sig = str(e.getMethod().getSignature())
      except Exception:
        sig = None
      if sig:
        print('[C] %s' % sig)
        if sig in TARGET_METHOD_SIGS:
          print('[+] target call hit: %s' % sig)

    try:
      subs = e.getSubElements()
    except Exception:
      return
    for sub in subs:
      self._scan_method(sub)
