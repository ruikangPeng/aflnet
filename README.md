# AFLNet:一种适用于网络协议的灰盒模糊器
AFLNet 是一个用于协议实现的灰盒模糊器。与现有的协议模糊器不同，它采用了一种变异方法，除了使用代码覆盖率反馈外，还使用状态反馈来指导模糊过程。AFLNet 以服务器和实际客户端之间记录的消息交换语料库为种子。不需要任何协议规范或消息语法。它充当客户端，重放发送到服务器的原始消息序列的变体，并保留那些在增加代码或状态空间覆盖率方面有效的变体。为了识别由消息序列执行的服务器状态，AFLNet 使用服务器的响应代码。从这个反馈中，AFLNet 识别了状态空间中的渐进区域，并系统地转向这些区域。

# 许可证

AFLNet 是根据 [Apache许可证2.0版](https://www.apache.org/licenses/LICENSE-2.0)授权的。

AFLNet 是 MichałZalewski 编写和维护的 [AFL](http://lcamtuf.coredump.cx/afl/) 的扩展<<lcamtuf@google.com>>。 有关 AFL 的详细信息，请参阅 [README-AFL.md](README-AFL.md)。

* **AFL**: [Copyright](https://github.com/aflsmart/aflsmart/blob/master/docs/README) 2013, 2014, 2015, 2016 Google Inc. All rights reserved. Released under terms and conditions of [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

# 引用 AFLNet
AFLNet 已被接受作为测试工具论文在 2020 年 IEEE 国际软件测试、验证和确认会议(ICST)上发表。

```
@inproceedings{AFLNet,
author={Van{-}Thuan Pham and Marcel B{\"o}hme and Abhik Roychoudhury},
title={AFLNet: A Greybox Fuzzer for Network Protocols},
booktitle={Proceedings of the 13rd IEEE International Conference on Software Testing, Verification and Validation : Testing Tools Track},
year={2020},}
```

# 安装(在 Ubuntu 18.04 和 16.04 64位上测试)

## 准备

```bash
# 安装 clang(根据 AFL/AFLNet 的要求启用 llvm_mode)
sudo apt-get install clang
# 安装 graphviz-dev
sudo apt-get install graphviz-dev libcap-dev
```

## AFLNet

下载 AFLNet 并编译它。我们已经在 Ubuntu 18.04 和 Ubuntu 16.04 64位上测试了 AFLNet，它也可以在所有支持 AFL 和 [graphviz](https://graphviz.org)的环境中工作。

```bash
# 首先，将这个 AFLNet 存储库克隆到一个名为 AFLNet 的文件夹中
git clone <links to the repository> aflnet
# 然后移动到源代码文件夹
cd aflnet
make clean all
cd llvm_mode
# 如果找不到 llvm-config，则以下 make 命令可能不起作用
# 要解决此问题，只需设置 LLVM_CONFIG 环境。变量到您机器上的特定 llvm 配置版本
# 在 Ubuntu 18.04上，如果你使用 apt-get 安装了 clang，它可能是 llvm-config-6.0
make
# 移动到 AFLNet 的父文件夹
cd ../..
export AFLNET=$(pwd)/aflnet
export WORKDIR=$(pwd)
```

## 设置 PATH 环境变量

```bash
export PATH=$PATH:$AFLNET
export AFL_PATH=$AFLNET
```

# Usage

AFLNet 为 AFL 添加了以下选项。运行 ```afl-fuzz --help```查看所有选项。有关这些 AFLNet 选项的常见问题，请参阅常见问题解答部分。

- ***-N netinfo***: 服务器信息(例如，tcp://127.0.0.1/8554)

- ***-P protocol***: 要测试的应用程序协议(例如，RTSP、FTP、DTLS12、DNS、DICOM、SMTP、SSH、TLS、DAP-HTTP、SIP)

- ***-D usec***: (可选)服务器完成初始化的等待时间(以微秒为单位)

- ***-e netnsname***: (可选)运行服务器的网络命名空间名称

- ***-K*** : (可选)在消耗完所有请求消息后，发送 SIGTERM 信号以正常终止服务器

- ***-E*** : (可选)启用状态感知模式

- ***-R*** : (可选)启用区域级突变运算符

- ***-F*** : (可选)启用假阴性还原模式

- ***-c script*** : (可选)用于服务器清理的脚本的名称或完整路径

- ***-q algo***: (可选)状态选择算法（例如:1. RANDOM_SELECTION，2. ROUND_ROBIN，3. FAVOR)

- ***-s algo***: (可选)种子选择算法（例如:1. RANDOM_SELECTION，2.ROUND_ROBIN，3. FAVOR)


命令示例： 
```bash
afl-fuzz -d -i in -o out -N <server info> -x <dictionary file> -P <protocol> -D 10000 -q 3 -s 3 -E -K -R <executable binary and its arguments (e.g., port number)>
```

# 教程-模糊测试 Live555 媒体流服务器

[Live555](http://live555.com)流媒体是一个用于多媒体流媒体的 C++ 库。该库支持诸如 RTP/RTCP 和 RTSP 之类的用于流传输的开放协议。它被广泛使用的媒体播放器(如 [VLC](https://videolan.org)和 [MPlayer](http://mplayerhq.hu))以及一些安全摄像头和网络录像机（如[DLink D-View Cameras](http://files.dlink.com.au/products/D-ViewCam/REV_A/Manuals/Manual_v3.51/D-ViewCam_DCS-100_B1_Manual_v3.51(WW).pdf), [Senstar Symphony](http://cdn.aimetis.com/public/Library/Senstar%20Symphony%20User%20Guide%20en-US.pdf), [WISENET Video Recorder](https://www.eos.com.au/pub/media/doc/wisenet/Manuals_QRN-410S,QRN-810S,QRN-1610S_180802_EN.pdf))内部使用。在这个例子中，我们展示了如何使用 AFLNet 模糊 Live555 并发现其 RTSP 服务器参考实现(testOnDemandRTSPServer)中的错误。将遵循类似的步骤来模糊实现其他协议(例如，FTP、SMTP、SSH)的服务器。

如果你想快速运行一些实验，请查看 [ProFuzzBench](https://github.com/profuzzbench/profuzzbench)。ProFuzzBench 包括一套用于流行协议(如TLS、SSH、SMTP、FTP、SIP)的代表性开源网络服务器，以及自动化实验的工具。

## Step-0. 服务器和客户端编译和设置

Live555 的最新源代码可以作为 tarball 在 [Live555 公共页面](http://live555.com/liveMedia/public/)上下载。GitHub 上还有一个库的[镜像](https://github.com/rgaufman/live555)。在这个例子中，我们选择模糊 [Live555 的旧版本](https://github.com/rgaufman/live555/commit/ceeb4f462709695b145852de309d8cd25e2dca01)，该版本于2018年8月28日提交到存储库。在模糊 Live555 的这个特定版本时，AFLNet 暴露了 Live555 中的四个漏洞，其中两个是零日漏洞。要编译和设置 Live555，请使用以下命令。

```bash
cd $WORKDIR
# 克隆 live555 存储仓库
git clone https://github.com/rgaufman/live555.git
# 进入 live555 文件夹下
cd live555
# 切换到 live555 的异常版本
git checkout ceeb4f4
# 应用补丁。请参阅以下补丁的详细说明
patch -p1 < $AFLNET/tutorials/live555/ceeb4f4.patch
# 生成 Makefile
./genMakefiles linux
# 编译源代码
make clean all
```

正如您从命令中看到的，我们应用了一个补丁来使服务器有效地模糊化。除了对生成 Makefile 的更改外，我们还对 Live555 中的随机会话 ID 生成进行了小更改，该 Makefile 使用 afl-clang-fast++ 来执行启用覆盖反馈的检测。在 Live555 的未修改版本中，它为每个连接生成一个会话 ID，该会话 ID 应包含在从连接的客户端发送的后续请求中。否则，请求会很快被服务器拒绝，这会导致模糊时路径无法确定。具体来说，由于会话 ID 正在更改，相同的消息序列可能会使用不同的服务器路径。我们通过修改 Live555 来处理这个特定问题，使其始终生成相同的会话 ID。

一旦 Live555 源代码成功编译，我们应该会看到测试中的服务器(testOnDemandRTSPServer)和位于 testProgs 文件夹中的示例 RTSP 客户端(testRTSPClient)。我们可以通过运行以下命令来测试服务器。

```bash
# 移动到保存 RTSP 服务器和客户端的文件夹
cd $WORKDIR/live555/testProgs
# 将示例媒体源文件复制到服务器文件夹
cp $AFLNET/tutorials/live555/sample_media_sources/*.* ./
# 在端口 8554 上运行 RTSP 服务器
./testOnDemandRTSPServer 8554
# 在另一个屏幕/终端上运行示例客户端
./testRTSPClient rtsp://127.0.0.1:8554/wavAudioTest
```

我们应该看到来自示例客户端的输出，显示它成功地连接到服务器，发送请求并接收响应，包括来自服务器的流数据。

## Step-1. 准备消息序列作为种子输入

AFLNet takes message sequences as seed inputs so we first capture some sample usage scenarios between the sample client (testRTSPClient) and the server under test (SUT). The following steps show how we prepare a seed input for AFLNet based on a usage scenario in which the server streams an audio file in WAV format to the client upon requests. The same steps can be followed to prepare other seed inputs for other media source files (e.g., WebM, MP3).

We first start the server under test

```bash
cd $WORKDIR/live555/testProgs
./testOnDemandRTSPServer 8554
```

After that, we ask [tcpdump data-network packet analyzer](https://www.tcpdump.org) to capture all traffics through the port opened by the server, which is 8554 in this case. Note that you may need to change the network interface that works for your setup using the ```-i``` option.

```bash
sudo tcpdump -w rtsp.pcap -i lo port 8554
```

Once both the server and tcpdump have been started, we run the sample client

```bash
cd $WORKDIR/live555/testProgs
./testRTSPClient rtsp://127.0.0.1:8554/wavAudioTest
```

When the client completes its execution, we stop tcpdump. All the requests and responses in the communication between the client and the server should be stored in the specified rtsp.pcap file. Now we use [Wireshark network analyzer](https://wireshark.org) to extract only the requests and use the request sequence as a seed input for AFLNet. Please install Wireshark if you haven't done so.

We first open the PCAP file with Wireshark.

```bash
wireshark rtsp.pcap
```

This is a screenshot of Wireshark. It shows packets (requests and responses) in multiple rows, one row for one packet.

![Analyzing the pcap file with Wireshark](tutorials/live555/images/rtsp_wireshark_1.png)

To extract the request sequence, we first do a right-click and choose Follow->TCP Stream.

![Follow TCP Stream](tutorials/live555/images/rtsp_wireshark_2.png)

Wireshark will then display all requests and responses in plain text.

![View requests and responses in plain text](tutorials/live555/images/rtsp_wireshark_3.png)

As we are only interested in the requests for our purpose, we choose incoming traffic to the SUT-opened port by selecting an option from the bottom-left drop-down list. We choose ```127.0.0.1:57998->127.0.0.1:8554``` in this example which askes Wireshark to display all request messages sent to port 8554.

![View requests in plain text](tutorials/live555/images/rtsp_wireshark_4.png)

Finally, we switch the data mode so that we can see the request sequence in raw (i.e., binary) mode. Click "Save as" and save it to a file, say rtsp_requests_wav.raw.

![View and save requests in raw binary](tutorials/live555/images/rtsp_wireshark_5.png)

The newly saved file rtsp_requests_wav.raw can be fed to AFLNet as a seed input. You can follow the above steps to create other seed inputs for AFLNet, say rtsp_requests_mp3.raw and so on. We have prepared a ready-to-use seed corpus in the tutorials/live555/in-rtsp folder.

## Step-2. Make modifications to the server code (optional)

Fuzzing network servers is challenging and in several cases, we may need to slightly modify the server under test to make it (effectively and efficiently) fuzzable. For example, this [blog post](http://www.vegardno.net/2017/03/fuzzing-openssh-daemon-using-afl.html) shows several modifications to OpenSSH server to improve the fuzzing performance including disable encryption, disable MAC and so on. In this tutorial, the RTSP server uses the same response code ```200``` for all successful client requests, no matter what actual server state is. So to make fuzzing more effective, we can apply [this simple patch](tutorials/live555/ceeb4f4_states_decomposed.patch) that decomposes the big state 200 into smaller states. It makes the inferred state machine more fine grained and hence AFLNet has more information to guide the state space exploration.

## Step-3. Fuzzing

```bash
cd $WORKDIR/live555/testProgs
afl-fuzz -d -i $AFLNET/tutorials/live555/in-rtsp -o out-live555 -N tcp://127.0.0.1/8554 -x $AFLNET/tutorials/live555/rtsp.dict -P RTSP -D 10000 -q 3 -s 3 -E -K -R ./testOnDemandRTSPServer 8554
```

Once AFLNet discovers a bug (e.g., a crash or a hang), a test case containing the message sequence that triggers the bug will be stored in ```replayable-crashes``` or ```replayable-hangs``` folder. In the fuzzing process, AFLNet State Machine Learning component keeps inferring the implmented state machine of the SUT and a .dot file (ipsm.dot) is updated accordingly so that the user can view that file (using a .dot viewer like xdot) to monitor the current progress of AFLNet in terms of protocol inferencing. Please read the AFLNet paper for more information.

## Step-4. Reproducing the crashes found

AFLNet has an utility (aflnet-replay) which can replay message sequences stored in crash and hang-triggering files (in ```replayable-crashes``` and ```replayable-hangs``` folders). Each file is structured in such a way that aflnet-replay can extract messages based on their size. aflnet-replay takes three parameters which are 1) the path to the test case generated by AFLNet, 2) the network protocol under test, and 3) the server port number. The following commands reproduce a PoC for [CVE-2019-7314](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7314).

```bash
cd $WORKDIR/live555/testProgs
# Start the server
./testOnDemandRTSPServer 8554
# Run aflnet-replay
aflnet-replay $AFLNET/tutorials/live555/CVE_2019_7314.poc RTSP 8554
```

To get more information about the discovered bug (e.g., crash call stack), you can run the buggy server with [GDB](https://gnu.org/software/gdb) or you can apply the Address Sanitizer-Enabled patch ($AFLNET/tutorials/live555/ceeb4f4_ASAN.patch) and recompile the server before running it. 

# FAQs

## 1. How do I extend AFLNet?

AFLNet has a modular design that makes it easy to be extended.

### 1.1. How do I add support for another protocol?

If you want to support another protocol, all you need is to follow the steps below.

#### Step-1. Implement 2 functions to parse the request and response sequences

You can use the available ```extract_requests_*``` and ```extract_response_codes_*``` functions as references. These functions should be declared and implemented in [aflnet.h](aflnet.h) and [aflnet.c](aflnet.c), respectively. Note that, please use the same function parameters.

#### Step-2. Update main function to support a new protocol

Please update the code that handles the ```-P``` option in the main function to support a new protocol.

### 1.2. How do I implement another search strategy?

It is quite straightforward. You just need to update the two functions ```choose_target_state``` and ```choose_seed```. The function ```update_scores_and_select_next_state``` may need an extension too. 

## 2. What happens if I don't enable the state-aware mode by adding -E option?

If ```-E``` is not enabled, even though AFLNet still manages the requests' boundaries information so it can still follow the sequence diagram of the protocol -- sending a request, waiting for a response and so on, which is not supported by normal networked-enabled AFL. However, in this setup AFLNet will ignore the responses and it does not construct the state machine from the response codes. As a result, AFLNet cannot use the state machine to guide the exploration.

## 3. When I need -c option and what I should write in the cleanup script?

You may need to provide this option to keep network fuzzing more deterministic. For example, when you fuzz a FTP server you need to clear all the files/folders created in the previous fuzzing iteration in the shared folder because if you do not do so, the server will not be able to create a file if it exists. It means that the FTP server will work differently when it receives the same sequence of requests from the client, which is AFLNet in this fuzzing setup. So basically the script should include commands to clean the environment affecting the behaviors of the server and give the server a clean environment to start.

## 4. What is false-negative reduction mode and when I should enable it using -F?

Unlike stateless programs (e.g., image processing libraries like LibPNG), several stateful servers (e.g., the RTSP server in the above tutorial) do not terminate themselves after consuming all requests from the client, which is AFLNet in this fuzzing setup. So AFLNet needs to gracefully terminate the server by sending the SIGTERM signal (when -K is specified). Otherwise, AFLNet will detect normal server executions as hangs. However, the issue is that if AFLNet sends SIGTERM signal too early, say right after all request messages have been sent to the server, the server may be forced to terminate when it is still doing some tasks which may lead to server crashes (i.e., false negatives -- the server crashes are missed). The false-negative reduction mode is designed to handle such situations. However, it could slow down the fuzzing process leading to slower execution speed.


