# miniOS

miniOS-project/  
├── README.md                   # 프로젝트 설명 및 사용 방법 문서  
├── Makefile                    # 전체 프로젝트 빌드 자동화를 위한 메이크파일  
├── boot/                       # 부트로더 소스 코드  
O   └── boot.asm                # 부트로더 어셈블리 코드  
├── kernel/                     # 커널 소스 코드  
O   ├── kernel.c                # 커널 메인 C 소스 파일  
O   ├── process.c               # 프로세스 코드   
O   ├── system.c                # 시스템 코드  
O   └── OS_project/             # 운영체제 프로젝트 파일  
O       ├── IPC_R.c             # 공유 메모리에서 메세지 출력 코드  
O       ├── IPC_W.c             # 공유 메모리 생성 및 메세지 저장 코드     
O       ├── OS_time.c           # 시스템 시간 설정 코드  
O       ├── creatdir.c          # 새로운 디렉토리 생성 코드   
O       ├── creatfile.c         # 파일 생성 코드  
O       ├── deletefile.c        # 파일 삭제 코드  
O       ├── deletedir.c         # 디렉토리 삭제 코드  
O       ├── filesystem.c        # 파일 시스템 구현 코드
O       ├── filesystem.h        # 파일 시스템 헤더파일 
O       ├── monitoring_cpu.c    # cpu 사용량 출력 코드  
O       ├── monitoring_memory.c # memory monitor 코드  
O       ├── signal_event.c      # 신호 생성 코드  
O       ├── socket_client.c     # 서버 통신 클라이언트 코드  
O       ├── socket_server.c     # TCP 서버 구현 코드  
O       ├── sys_abort.c         # abort 실행 코드  
O       ├── sys_exec.c          # 프로세스 실행 코드  
O       ├── sys_exit.c          # 프로세스 종료 코드  
O       ├── sys_fork.c          # fork 생성 코드  
O       ├── sys_getpid.c        # 현재 프로세스 ID 출력 코드  
O       ├── sys_getppid.c       # 부모 프로세스 ID 출력 코드  
O       ├── sys_kill.c          # 특정 프로세스에 시그널 입력 코드    
O       ├── sys_wait.c          # 자식 프로세스의 종료 대기 코드    
O       ├── syscall.h           # 시스템콜 헤더파일  
O       ├── wait_event.c        # 이벤트 발생까지 블로킹 상태 대기 코드  
O       ├── wait_time.c         # 지정 시간 동안 대기 코드  
O       └── writefile.c         # 파일에 데이터 작성  
├── drivers/                    # 디바이스 드라이버 코드  
O   └── basic_driver.c          # 기본 드라이버  
├── lib/                        # 커널 라이브러리 및 공통 유틸리티  
O   └── basic_lib.c             # 기본 라이브러리  
├── include/                    # 헤더 파일  
O   ├── kernel.h                # 커널 관련 공통 헤더  
O   ├── drivers/                # 드라이버 헤더 파일  
O   └── lib/                    # 라이브러리 헤더 파일  
└── scripts/                    # 빌드 및 유틸리티 스크립트  
O   ├── build.sh                # 빌드 스크립트  
O   └── run_qemu.sh             # QEMU를 통해 OS 이미지 실행 스크립트  
