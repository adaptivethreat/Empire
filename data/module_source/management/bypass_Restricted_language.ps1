Set-ExecutionPolicy RemoteSigned -Scope Process
      
 Set-ExecutionPolicy RemoteSigned -Scope Process -Force -Verbose | Invoke-AsWorkflow -CommandName calc.exe
sleep 3.22
