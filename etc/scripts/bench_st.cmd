@echo off
cd /d "%~dp0"

cargo clean
cargo bench --no-run

for %%i in (8192 16384 32768 65536 131072) do (
    set PCG64DXSM_ST_BUFFER_SIZE=%%~i
    cargo bench --bench rng_bench -- --st | .\bin\tee-x64.exe result_st.%%~i.log
    echo.
)

pause
