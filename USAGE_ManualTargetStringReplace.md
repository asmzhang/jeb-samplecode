# ManualTargetStringReplace 使用说明

## 概述

[ManualTargetStringReplace.py](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/ManualTargetStringReplace.py) 会在当前 JEB 会话里，把目标解密调用直接替换成明文字符串常量。

它依赖外部 Java helper：

- [decode-1.0-SNAPSHOT.jar](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/decode/build/libs/decode-1.0-SNAPSHOT.jar)
- [decode_targets.json](/d:/tools/JEB_demo_5.36.0.202601300012_by_CXV/jeb-samplecode/decode/src/main/resources/decode_targets.json)

## 当前支持的目标函数

- `Lcom/mbridge/msdk/shell/MBService;->oOoooOoooOOOooo([B[B)Ljava/lang/String;`
- `Li1iIiI1iIiIiIiiI1iI;->oOoooOoooOOOooo([B[B)Ljava/lang/String;`
- `LiiIiiiI1i1iI1iIiI;->oOoooOoooOOOooo([B[B)Ljava/lang/String;`

## 工作方式

脚本会：

1. 在当前 JEB 反编译后的 Java AST 中找到目标调用
2. 提取两个 `byte[]` 实参
3. 调用外部 jar，传入原始 DEX/Smali 签名和参数
4. 取回明文字符串
5. 直接替换当前 Java AST
6. 刷新 JEB 视图

## 前提条件

- `JAVA_HOME` 指向可用 JDK
- jar 已经编译完成：
  [decode-1.0-SNAPSHOT.jar](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/decode/build/libs/decode-1.0-SNAPSHOT.jar)
- JEB 里已经打开并反编译了目标 APK/DEX 的 Java 代码

## decode 工程

源码位置：

- [DecodeHelper.java](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/decode/src/main/java/com/awahmh/decode/DecodeHelper.java)
- [i1iIiI1iIiIiIiiI1iI.java](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/decode/src/main/java/com/awahmh/decode/i1iIiI1iIiIiIiiI1iI.java)
- [MBService.java](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/decode/src/main/java/com/awahmh/decode/MBService.java)
- [decode_targets.json](/d:/tools/JEB_demo_5.36.0.202601300012_by_CXV/jeb-samplecode/decode/src/main/resources/decode_targets.json)

构建命令：

```powershell
cd D:\Apps\com.awahmh.qcmpkbcuhv\jeb-samplecode\decode
gradlew.bat clean jar
```

产物位置：

- [decode-1.0-SNAPSHOT.jar](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/decode/build/libs/decode-1.0-SNAPSHOT.jar)

## 与 decode 工程的配合关系

`ManualTargetStringReplace.py` 和 `decode` 工程是配套使用的：

### 1. decode 工程负责什么

`decode` 目录下的 Java 工程负责真正执行解密逻辑：

- [DecodeHelper.java](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/decode/src/main/java/com/awahmh/decode/DecodeHelper.java)
  负责命令行入口、参数解析、读取 `decode_targets.json`、反射调用
- [i1iIiI1iIiIiIiiI1iI.java](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/decode/src/main/java/com/awahmh/decode/i1iIiI1iIiIiIiiI1iI.java)
  对应 `Li1iIiI1iIiIiIiiI1iI;->oOoooOoooOOOooo([B[B)Ljava/lang/String;`
- [MBService.java](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/decode/src/main/java/com/awahmh/decode/MBService.java)
  对应 `Lcom/mbridge/msdk/shell/MBService;->oOoooOoooOOOooo([B[B)Ljava/lang/String;`
- [decode_targets.json](/d:/tools/JEB_demo_5.36.0.202601300012_by_CXV/jeb-samplecode/decode/src/main/resources/decode_targets.json)
  是 Python 脚本和 Java helper 共用的目标注册表

### 2. ManualTargetStringReplace.py 负责什么

[ManualTargetStringReplace.py](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/ManualTargetStringReplace.py) 不负责真正的解密算法执行，它负责：

1. 在 JEB Java AST 里找到目标调用
2. 提取两个 `byte[]` 参数
3. 调用 `decode/build/libs/decode-1.0-SNAPSHOT.jar`
4. 取回字符串结果
5. 回填替换当前 Java AST

### 3. 调用协议

脚本调用 jar 的方式是：

```text
java -jar decode-1.0-SNAPSHOT.jar invoke --target <DEX签名> --arg <arg1> --arg <arg2>
```

例如：

```text
invoke
--target Li1iIiI1iIiIiIiiI1iI;->oOoooOoooOOOooo([B[B)Ljava/lang/String;
--arg 118,-60,-71
--arg 3,-74,-43,1,25,-37,-105,32,60,101,18
```

### 4. DEX 签名映射

脚本传给 jar 的是原始样本里的 DEX/Smali 签名，不是 `decode` 工程里的类名。

`decode_targets.json` 会把原始签名映射到 `decode` 工程里的实际实现类，例如：

- `Li1iIiI1iIiIiIiiI1iI;->oOoooOoooOOOooo([B[B)Ljava/lang/String;`
  映射到
- `com.awahmh.decode.MBService`

- `LiiIiiiI1i1iI1iIiI;->oOoooOoooOOOooo([B[B)Ljava/lang/String;`
  映射到
- `com.awahmh.decode.MBService`

以及：

- `Lcom/mbridge/msdk/shell/MBService;->oOoooOoooOOOooo([B[B)Ljava/lang/String;`
  映射到
- `com.awahmh.decode.MBService`

所以：

- 脚本层不需要知道 `decode` 工程内部类名
- 只需要传原始 DEX 签名
- `decode` 工程内部自己完成签名分发

### 5. 修改任一侧时要注意什么

如果你修改了 `decode` 工程源码：

1. 重新构建 jar
2. 确认产物仍在：
   [decode-1.0-SNAPSHOT.jar](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/decode/build/libs/decode-1.0-SNAPSHOT.jar)

如果你新增新的目标解密函数：

1. 在 [ManualTargetStringReplace.py](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/ManualTargetStringReplace.py) 的 `TARGET_METHOD_SIGS` 里加入原始 DEX 签名
2. 在 [decode_targets.json](/d:/tools/JEB_demo_5.36.0.202601300012_by_CXV/jeb-samplecode/decode/src/main/resources/decode_targets.json) 里加入 `dexSig -> implClass` 映射
3. 如果需要，新增对应 Java 实现类
4. 重新构建 jar

## 脚本模式

脚本顶部有默认模式配置：

```python
DEFAULT_MODE = 'all'
```

可选值：

- `method`
  只处理当前光标所在方法
- `class`
  处理当前类全部方法
- `all`
  处理全项目全部 Java 单元
- `auto`
  光标在方法里就处理当前方法，否则处理当前类

## 在 JEB 中运行

在 JEB 里执行：

- [ManualTargetStringReplace.py](/d:/Apps/com.awahmh.qcmpkbcuhv/jeb-samplecode/ManualTargetStringReplace.py)

可以通过脚本参数覆盖默认模式：

- `method`
- `class`
- `all`

例如：

### 当前方法

```text
method
```

### 当前类

```text
class
```

### 全项目

```text
all
```

## 日志说明

正常日志包括：

- `[*] Mode: ...`
- `[*] Focused method: ...`
- `[+] <DEX签名> => '明文'`
- `[*] Processed N Java units`
- `[*] Replaced M calls`

失败时会有：

- `[!] decode failed: <DEX签名>`

## 生效结果

命中调用后，脚本会：

- 直接替换 Java AST
- 调用 `notifyGenericChange()`
- 让 JEB Decompiled Java 视图立即显示明文

## 限制

- 当前主要处理“在 Java AST 中能恢复出两个 `byte[]` 实参”的调用
- 更复杂的参数来源不一定能替换
- 当前方案是稳定的手动/批量回填方案，不是 JEB plugin 自动流水线方案
