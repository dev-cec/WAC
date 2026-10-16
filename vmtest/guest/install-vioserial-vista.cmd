@echo off
rem install-vioserial-vista.cmd: TEST VM ONLY. Installs, on Windows Vista
rem (no PowerShell), the virtio-serial driver the guest agent's channel needs:
rem the root of its signing chain and its publisher trusted first, so that
rem pnputil asks nothing. Run by create-vm.sh from the answer file's medium,
rem which also carries the driver (vioserial\) and both certificates; each
rem step's result goes to %SystemRoot%\Temp\wac-vioserial.log.
set LOG=%SystemRoot%\Temp\wac-vioserial.log
set MEDIUM=%~d0
echo medium %MEDIUM% > %LOG%
certutil -addstore Root %MEDIUM%\digicert-root.cer >> %LOG% 2>&1
echo certutil Root: %errorlevel% >> %LOG%
rem -f: a Vista that never trusted a publisher has no TrustedPublisher store
rem yet, and certutil does not create it without (measured).
certutil -f -addstore TrustedPublisher %MEDIUM%\vioser-publisher.cer >> %LOG% 2>&1
echo certutil TrustedPublisher: %errorlevel% >> %LOG%
pnputil -i -a %MEDIUM%\vioserial\vioser.inf >> %LOG% 2>&1
echo pnputil: %errorlevel% >> %LOG%
