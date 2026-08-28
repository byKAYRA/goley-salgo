@echo off
echo =======================================================
echo Goley Server Projesi Derleniyor (APP\CALENTON\release)...
echo =======================================================
cargo build --release

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [HATA] Derleme sirasinda bir sorun olustu!
    pause
    exit /b %ERRORLEVEL%
)

if not exist "APP\CALENTON\release" mkdir "APP\CALENTON\release"
copy /Y "APP\release\server-launcher.exe" "APP\CALENTON\release\" >nul
copy /Y "APP\release\goley-server.exe" "APP\CALENTON\release\" >nul
copy /Y "APP\release\server.exe" "APP\CALENTON\release\" 2>nul
copy /Y "APP\release\patchd.exe" "APP\CALENTON\release\" >nul
copy /Y "APP\release\gly-extract.exe" "APP\CALENTON\release\" >nul
copy /Y "APP\release\gly-cov.exe" "APP\CALENTON\release\" >nul

echo.
echo [BASARILI] Derleme tamamlandi!
echo Cikti Klasoru: APP\CALENTON\release\
echo.
pause
