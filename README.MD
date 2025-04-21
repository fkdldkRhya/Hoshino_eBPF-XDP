# Hoshino eBPF XDP 포트 차단기

이 프로젝트는 eBPF XDP를 사용하여 네트워크 인터페이스에서 특정 포트로 들어오는 패킷을 차단(drop)하는 간단한 프로그램을 제공합니다
## 개발자 소개   
|                                              최시훈                                              |
| :----------------------------------------------------------------------------------------------: |
|                  <img width="160px" src="https://github.com/fkdldkrhya.png" />                   |
| [@fkdldkrhya](https://github.com/fkdldkrhya) <br> 한양대학교 ERICA 3학년   |                 

## 사전 요구사항

이 프로젝트를 빌드하고 실행하기 위해서는 다음이 필요합니다:

- Linux 커널 5.3 이상 (XDP 지원)
- LLVM 및 Clang (BPF 컴파일용)
- libbpf 개발 패키지
- 사용 중인 배포판의 `bpf-headers` 패키지

Ubuntu 또는 Debian 시스템에서는 다음 명령으로 종속성을 설치할 수 있습니다:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev gcc-multilib build-essential \
                        linux-headers-$(uname -r) libbpf-dev
```

## 빌드 방법

프로젝트를 빌드하려면 다음 명령을 실행하세요:

```bash
make
```

이 명령은 XDP 프로그램(`xdp_port_drop.o`)과 로더 프로그램(`xdp_loader`)을 모두 컴파일합니다.

## 사용법

```
./xdp_loader [OPTION]
```

### 옵션:

- `-i IFNAME`: XDP 프로그램을 연결할 네트워크 인터페이스 지정 (필수)
- `-p PORT`: 차단할 대상 포트 지정 (여러 번 사용 가능, 최대 10개 포트, 기본값: 8080)
- `-u`: 인터페이스에서 XDP 프로그램 언로드
- `-h`: 도움말 표시 및 종료

### 예제:

eth0 인터페이스에서 기본 포트(8080)를 차단하는 XDP 프로그램 로드:

```bash
sudo ./xdp_loader -i eth0
```

eth0 인터페이스에서 여러 포트(80, 443, 8080)를 차단하는 XDP 프로그램 로드:

```bash
sudo ./xdp_loader -i eth0 -p 80 -p 443 -p 8080
```

eth0 인터페이스에서 XDP 프로그램 언로드:

```bash
sudo ./xdp_loader -i eth0 -u
```

## 작동 방식

XDP 프로그램은 Linux 커널의 네트워킹 서브시스템에서 처리되기 전, 네트워크 스택의 가장 빠른 지점에서 들어오는 패킷을 검사합니다. TCP 및 UDP 패킷을 모두 검사하고 목적지 포트가 구성된 차단 포트와 일치하는 패킷을 드롭합니다.

이 프로그램이 효율적인 이유:

1. XDP 훅에서 작동하여 패킷을 가장 빠르게 처리할 수 있습니다
2. 일치하지 않는 패킷은 빠르게 통과시킵니다
3. 특정 포트에 대한 패킷만 드롭하므로 다른 트래픽에는 영향을 주지 않습니다

## 제한사항

- 이 프로그램은 IPv4 트래픽만 처리합니다
- 단편화된 IP 패킷은 처리하지 않습니다
- 컴파일을 위해 실행 중인 커널 버전과 일치하는 커널 헤더가 필요할 수 있습니다
