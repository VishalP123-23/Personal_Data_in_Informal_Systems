@echo off
cd /d "%~dp0backend"
"C:\Program Files\PostgreSQL\16\bin\pg_ctl.exe" start -D "%~dp0work\pgdata" -l "%~dp0work\postgres.log" -o "-h 127.0.0.1 -p 55432" -w
.venv\Scripts\python.exe -m alembic upgrade head
if errorlevel 1 goto failed
.venv\Scripts\python.exe -m app.seed_demo
if errorlevel 1 goto failed
echo Open http://127.0.0.1:8001 in your browser. Keep this window open.
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
:failed
pause
