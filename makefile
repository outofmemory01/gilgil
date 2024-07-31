# 컴파일러
CC = gcc

# 컴파일 옵션
CFLAGS = -Wall -g

# 라이브러리 옵션
LDFLAGS = -lpcap

# 소스 파일
SRCS = net.c

# 오브젝트 파일
OBJS = $(SRCS:.c=.o)

# 실행 파일 이름
TARGET = net

# 기본 타겟
all: $(TARGET)

# 실행 파일 빌드 규칙
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# 오브젝트 파일 빌드 규칙
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 클린 규칙
clean:
	rm -f $(OBJS) $(TARGET)

