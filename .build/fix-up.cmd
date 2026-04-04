@echo off
cd /d "%~dp0.."

cargo clean || goto:error
cargo upgrade --recursive --incompatible || goto:error
cargo update || goto:error
cargo fmt --all || goto:error
cargo clippy --all-targets --all-features || goto:error
cargo build --release || goto:error

echo.
echo Completed successfully.
echo.
pause
goto:eof

:error
echo.
echo Error: Something went wrong!
echo.
pause
exit /b 1
