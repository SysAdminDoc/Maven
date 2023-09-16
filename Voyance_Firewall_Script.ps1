netsh advfirewall firewall add rule name= "Vpacs_9001" dir=in action=allow protocol=TCP localport=9001

netsh advfirewall firewall add rule name="VPACS_out" dir=out action=allow program="C:\Program Files\VPACS\VPACS.exe" enable=yes profile=Private
netsh advfirewall firewall add rule name="VPACS_out" dir=out action=allow program="C:\Program Files\VPACS\VPACS.exe" enable=yes profile=Public
netsh advfirewall firewall add rule name="VPACS_out" dir=out action=allow program="C:\Program Files\VPACS\VPACS.exe" enable=yes profile=Domain

netsh advfirewall firewall add rule name="VPACS_in" dir=in action=allow program="C:\Program Files\VPACS\VPACS.exe" enable=yes profile=Private
netsh advfirewall firewall add rule name="VPACS_in" dir=in action=allow program="C:\Program Files\VPACS\VPACS.exe" enable=yes profile=Public
netsh advfirewall firewall add rule name="VPACS_in" dir=in action=allow program="C:\Program Files\VPACS\VPACS.exe" enable=yes profile=Domain

netsh advfirewall firewall add rule name="Voyance_in" dir=in action=allow program="C:\Program Files\Voyance\Voyance.exe" enable=yes profile=Private
netsh advfirewall firewall add rule name="Voyance_in" dir=in action=allow program="C:\Program Files\Voyance\Voyance.exe" enable=yes profile=Public
netsh advfirewall firewall add rule name="Voyance_in" dir=in action=allow program="C:\Program Files\Voyance\Voyance.exe" enable=yes profile=Domain

netsh advfirewall firewall add rule name="Voyance_out" dir=out action=allow program="C:\Program Files\Voyance\Voyance.exe" enable=yes profile=Private
netsh advfirewall firewall add rule name="Voyance_out" dir=out action=allow program="C:\Program Files\Voyance\Voyance.exe" enable=yes profile=Public
netsh advfirewall firewall add rule name="Voyance_out" dir=out action=allow program="C:\Program Files\Voyance\Voyance.exe" enable=yes profile=Domain

netsh advfirewall firewall add rule name="ECali1" dir=in action=allow program="C:\ecali1\ecali1.exe" enable=yes profile=Private
netsh advfirewall firewall add rule name="ECali1" dir=in action=allow program="C:\ecali1\ecali1.exe" enable=yes profile=Public
netsh advfirewall firewall add rule name="ECali1" dir=in action=allow program="C:\ecali1\ecali1.exe" enable=yes profile=Domain

netsh advfirewall firewall add rule name="CodeSite Dispatcher" dir=in action=allow program="C:\ecali1\csdispatcher.exe" enable=yes profile=Private
netsh advfirewall firewall add rule name="CodeSite Dispatcher" dir=in action=allow program="C:\ecali1\csdispatcher.exe" enable=yes profile=Public
netsh advfirewall firewall add rule name="CodeSite Dispatcher" dir=in action=allow program="C:\ecali1\csdispatcher.exe" enable=yes profile=Domain

