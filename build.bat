@echo off
echo Building Lab 3 programs...

REM Check if g++ is available
where g++ >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: g++ not found. Please install MinGW or add it to PATH.
    pause
    exit /b 1
)

REM Build Experiment A
echo Building Experiment A...
g++ -std=c++11 -Wall -O2 -o sender_a.exe sender.cpp -lws2_32 -lssl -lcrypto
g++ -std=c++11 -Wall -O2 -o receiver_a.exe receiver.cpp -lws2_32 -lssl -lcrypto

REM Build Experiment B
echo Building Experiment B...
g++ -std=c++11 -Wall -O2 -o sender_b.exe senderB.cpp -lws2_32 -lssl -lcrypto
g++ -std=c++11 -Wall -O2 -o receiver_b.exe receiverB.cpp -lws2_32 -lssl -lcrypto

REM Build Experiment C
echo Building Experiment C...
g++ -std=c++11 -Wall -O2 -o sender_c.exe senderC.cpp -lws2_32 -lssl -lcrypto
g++ -std=c++11 -Wall -O2 -o receiver_c.exe receiverC.cpp -lws2_32 -lssl -lcrypto

REM Build performance test
echo Building performance test...
g++ -std=c++11 -Wall -O2 -o test_performance.exe test_performance.cpp -lws2_32 -lssl -lcrypto

REM Build test file generator
echo Building test file generator...
g++ -std=c++11 -Wall -O2 -o generate_test_file.exe generate_test_file.cpp

echo.
echo Build complete!
echo.
echo Note: If your .exe files crash on startup, Windows cannot find the OpenSSL DLLs.
echo Please copy libssl-X-x64.dll and libcrypto-X-x64.dll from your MinGW/bin folder into this directory.
pause