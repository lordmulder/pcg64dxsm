@echo off
cd /d "%~dp0"

cargo clean
cargo bench --no-run

for %%k in (4 8 16 32 64) do (
	for %%i in (16384 32768 65536 131072) do (
		set PCG64DXSM_MT_BUFFER_SIZE=%%~i
		set PCG64DXSM_MT_NUM_BUFFERS=%%~k
		cargo bench --bench rng_bench -- --mt | .\bin\tee-x64.exe result_mt.%%~k.%%~i.log
		echo.
	)
)

pause
