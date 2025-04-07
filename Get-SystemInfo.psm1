# ++++++++++++++++++++++++++++++++++++
# +  Get-SystemInfo                  +
# +  Author: Andrew Powell           +
# +  github.com/andrewmichaelpowell  +
# ++++++++++++++++++++++++++++++++++++

If(-Not(Get-Module -Name "ActiveDirectory")){
  If(Get-Module -ListAvailable -Name "ActiveDirectory"){
    Import-Module -Name "ActiveDirectory"
    $RSAT = 1
  }

  Else{
    $RSAT = 0
  }
}

Else{
  $RSAT = 1
}

Function Get-SystemInfo{
  Param(
    [Parameter(Mandatory="True")]
    [String]$Computer
  )

  If(Test-Connection -ComputerName $Computer -Count 1 -Quiet){
    Try{
      $IP = Resolve-DNSName -ErrorAction Stop -Name $Computer | Select -Property IPAddress,NameHost

      Try{
        $Model = Get-WmiObject -ErrorAction Stop -ComputerName $Computer -Class Win32_ComputerSystem | Select-Object -Property Model
        $Serial = Get-WmiObject -ErrorAction Stop -ComputerName $Computer -Class Win32_BIOS | Select-Object -Property SerialNumber
        $OS = Get-WmiObject -ErrorAction Stop -ComputerName $Computer -Class Win32_OperatingSystem | Select-Object -Property Caption,OSArchitecture
        $Key = Get-WmiObject -ErrorAction Stop -ComputerName $Computer -Query 'Select * From SoftwareLicensingService' | Select-Object -Property OA3xOriginalProductKey
        $Cores = Get-WmiObject -ErrorAction Stop -ComputerName $Computer -Class Win32_Processor | Select-Object -Property NumberOfCores
        $LastUser = ((Get-ChildItem \\$Computer\C$\Users -Exclude "Administrator","Default","Public" | Sort-Object -Property LastWriteTime -Descending | Select-Object -Property Name -First 1).Name).ToLower()
        $BitlockerPercentRaw = Invoke-Command -ErrorAction Stop -ScriptBlock {manage-bde -ComputerName $Computer -Status c:} | Select-Object -First 12 | Select-Object -Skip 11
        $BitlockerPercent = $BitlockerPercentRaw.Substring(($BitlockerPercentRaw.IndexOf(":") + 2) , ($BitlockerPercentRaw.IndexOf("%") - ($BitLockerPercentRaw.IndexOf(":") + 1)))
        $BitlockerStatusRaw = Invoke-Command -ErrorAction Stop -ScriptBlock {manage-bde -ComputerName $Computer -Status c:} | Select-Object -First 14 | Select-Object -Skip 13
        $BitlockerStatus = $BitlockerStatusRaw.Substring(($BitlockerStatusRaw.IndexOf(":") + 16) , ($BitlockerStatusRaw.Length - ($BitlockerStatusRaw.IndexOf(":") + 16)))
        $TPMVersion = Get-WmiObject -ErrorAction Stop -ComputerName $Computer -Class Win32_TPM -Namespace "root\CIMV2\Security\MicrosoftTpm" | Select-Object -Property SpecVersion
	$SystemRestore = Get-WmiObject -ErrorAction Stop -ComputerName $Computer -Namespace "root\default" -Class SystemRestoreConfig | Select-Object -Property RPSessionInterval

        If($LastUser.IndexOf(".") -gt 0){
            $LastUser = $LastUser.Substring(0, $LastUser.IndexOf("."))
        }

        If($RSAT -eq 1){
          Try{
            $LastUser = Get-ADUser -Identity $LastUser -Property * | Select-Object -Property Name,Department,Office,OfficePhone,EmailAddress
          }

          Catch{
          }
        }

        $MAC = Get-WmiObject -ErrorAction Stop -ComputerName $Computer -Class Win32_NetworkAdapterConfiguration | Select-Object -Property MacAddress,Description | Where -Property MacAddress -Like "*:*:*:*:*:*"
        $Printer = Get-WmiObject -ErrorAction Stop -ComputerName $Computer -Class Win32_Printer | Select-Object -Property PortName,Name | Where -Property PortName -Like "*.*.*.*"

        Write-Host ""
        Write-Host -ForegroundColor Cyan "System Information"
        Write-Host ""
        Write-Host -NoNewLine "Name".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "
        If($IP.IPAddress){
          Write-Host -ForegroundColor White $Computer.ToLower()
        }

        Else{
          If(($IP.NameHost).IndexOf(".") -gt 0){
            Write-Host -ForegroundColor White (($IP.NameHost).Substring(0, ($IP.NameHost).IndexOf("."))).ToLower()
          }

          Else{
            Write-Host -ForegroundColor White ($IP.NameHost).ToLower()
          }
        }

        Write-Host -NoNewLine "IP".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "

        If($IP.IPAddress){
          Write-Host -ForegroundColor White $IP.IPAddress
        }

        Else{
          Write-Host -ForegroundColor White $Computer.ToLower()
        }

        Write-Host -NoNewLine "Model".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "
        Write-Host -ForegroundColor White $Model.Model
        Write-Host -NoNewLine "Serial".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "
        Write-Host -ForegroundColor White $Serial.SerialNumber
        Write-Host -NoNewLine "OS".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "
        Write-Host -ForegroundColor White $OS.Caption$OS.OSArchitecture
        Write-Host -NoNewLine "Product Key".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "

        If($Key.OA3xOriginalProductKey){
          Write-Host -ForegroundColor White $Key.OA3xOriginalProductKey
        }

        Else{
          Write-Host -ForegroundColor White "N/A"
        }

        Write-Host -NoNewLine "Processor Cores".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "
        Write-Host -ForegroundColor White $Cores.NumberOfCores
        Write-Host -NoNewLine "Bitlocker Status".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "
        Write-Host -ForegroundColor White $BitlockerStatus
        Write-Host -NoNewLine "Bitlocker Percent".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "
        Write-Host -ForegroundColor White $BitlockerPercent
        Write-Host -NoNewLine "TPM Version".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "

        If($TPMVersion.SpecVersion){
          Write-Host -ForegroundColor White ($TPMVersion.SpecVersion).Substring(0,3)
        }

        Else{
          Write-Host -ForegroundColor White "N/A"
        }

        Write-Host -NoNewLine "System Restore".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "

        If($SystemRestore.RPSessionInterval -eq 0){
          Write-Host -ForegroundColor White "Off"
        }

        Else{
          Write-Host -ForegroundColor White "On"
        }

        If($RSAT -eq 1){
          Write-Host -NoNewLine "Last User".PadRight(17)
          Write-Host -NoNewLine -ForegroundColor Red " : "

          If($LastUser.Name){
            Write-Host -ForegroundColor White $LastUser.Name
          }

          Else{
            Write-Host -ForegroundColor White "$LastUser"
          }

          Write-Host -NoNewLine "Location".PadRight(17)
          Write-Host -NoNewLine -ForegroundColor Red " : "

          If($LastUser.Office){
            Write-Host -ForegroundColor White $LastUser.Office
          }

          Else{
            Write-Host -ForegroundColor White "N/A"
          }

          Write-Host -NoNewLine "Department".PadRight(17)
          Write-Host -NoNewLine -ForegroundColor Red " : "

          If($LastUser.Department){
            Write-Host -ForegroundColor White $LastUser.Department
          }

          Else{
            Write-Host -ForegroundColor White "N/A"
          }

          Write-Host -NoNewLine "Phone".PadRight(17)
          Write-Host -NoNewLine -ForegroundColor Red " : "

          If($LastUser.OfficePhone){
            Write-Host -ForegroundColor White $LastUser.OfficePhone
          }

          Else{
            Write-Host -ForegroundColor White "N/A"
          }

          Write-Host -NoNewLine "Email".PadRight(17)
          Write-Host -NoNewLine -ForegroundColor Red " : "

          If($LastUser.EmailAddress){
            Write-Host -ForegroundColor White ($LastUser.EmailAddress).ToLower()
          }

          Else{
            Write-Host -ForegroundColor White "N/A"
          }
        }

        Else{
          Write-Host -NoNewLine "Last User".PadRight(17)
          Write-Host -NoNewLine -ForegroundColor Red " : "
          Write-Host -ForegroundColor White $LastUser.ToLower()
          Write-Host ""
          Write-Host -ForegroundColor Yellow "Install Microsoft Remote Server Administration Tools for detailed user information."
        }

        Write-Host ""
        Write-Host -ForegroundColor Cyan "MAC Addresses"
        Write-Host ""

        ForEach($MAC in $MAC){
          Write-Host -NoNewLine $MAC.MacAddress
          Write-Host -NoNewLine -ForegroundColor Red " : "
          Write-Host -ForegroundColor White $MAC.Description
        }

        Write-Host ""
        Write-Host -ForegroundColor Cyan "Network Printers"
        Write-Host ""

        If($Printer){
          ForEach ($Printer in $Printer){
            Write-Host -NoNewLine ($Printer.PortName).PadRight(17)
            Write-Host -NoNewLine -ForegroundColor Red " : "
            Write-Host -ForegroundColor White $Printer.Name
          }
        }

        Else{
          Write-Host -NoNewLine -ForegroundColor Yellow "Host "
          Write-Host -NoNewLine -ForegroundColor White $Computer.ToLower()
          Write-Host -ForegroundColor Yellow " does not have any installed network printers."
        }
      }
      Catch{
        Write-Host ""
        Write-Host -ForegroundColor Cyan "System Information"
        Write-Host ""
        Write-Host -NoNewLine "Name".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "
        If($IP.IPAddress){
          Write-Host -ForegroundColor White $Computer.ToLower()
        }

        Else{
          If(($IP.NameHost).IndexOf(".") -gt 0){
            Write-Host -ForegroundColor White (($IP.NameHost).Substring(0, ($IP.NameHost).IndexOf("."))).ToLower()
          }

          Else{
            Write-Host -ForegroundColor White ($IP.NameHost).ToLower()
          }
        }

        Write-Host -NoNewLine "IP".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "

        If($IP.IPAddress){
          Write-Host -ForegroundColor White $IP.IPAddress
        }

        Else{
          Write-Host -ForegroundColor White $Computer.ToLower()
        }

        Write-Host ""
        Write-Host -NoNewLine -ForegroundColor Yellow "Host "
        Write-Host -NoNewLine -ForegroundColor White $Computer.ToLower()
        Write-Host -ForegroundColor Yellow " is online, but the RPC service is not available."
      }
    }

    Catch{
        Write-Host ""
        Write-Host -NoNewLine -ForegroundColor Yellow "Host "
        Write-Host -NoNewLine -ForegroundColor White $Computer.ToLower()
        Write-Host -ForegroundColor Yellow " is online, but it does not have a DNS record."
    }
  }

  Else{
    Try{
      $IP = Resolve-DNSName -ErrorAction Stop -Name $Computer | Select -Property IPAddress,NameHost

      If($IP.IPAddress){
        Write-Host ""
        Write-Host -ForegroundColor Cyan "System Information"
        Write-Host ""
        Write-Host -NoNewLine "Name".PadRight(17)
        Write-Host -NoNewLine -ForegroundColor Red " : "
        Write-Host -ForegroundColor White $Computer.ToLower()
      }

      Else{
        If(($IP.NameHost).IndexOf(".") -gt 0){
          Write-Host ""
          Write-Host -ForegroundColor Cyan "System Information"
          Write-Host ""
          Write-Host -NoNewLine "Name".PadRight(17)
          Write-Host -NoNewLine -ForegroundColor Red " : "
          Write-Host -ForegroundColor White (($IP.NameHost).Substring(0, ($IP.NameHost).IndexOf("."))).ToLower()
        }

        Else{
          Write-Host ""
          Write-Host -ForegroundColor Cyan "System Information"
          Write-Host ""
          Write-Host -NoNewLine "Name".PadRight(17)
          Write-Host -NoNewLine -ForegroundColor Red " : "
          Write-Host -ForegroundColor White ($IP.NameHost).ToLower()
        }
      }

      Write-Host -NoNewLine "IP".PadRight(17)
      Write-Host -NoNewLine -ForegroundColor Red " : "

      If($IP.IPAddress){
        Write-Host -ForegroundColor White $IP.IPAddress
      }

      Else{
        Write-Host -ForegroundColor White $Computer.ToLower()
      }

      Write-Host ""
      Write-Host -NoNewLine -ForegroundColor Yellow "Host "
      Write-Host -NoNewLine -ForegroundColor White $Computer.ToLower()
      Write-Host -ForegroundColor Yellow " has a DNS record, but it is currently offline."
    }

    Catch{
      Write-Host ""
      Write-Host -NoNewLine -ForegroundColor Yellow "Host "
      Write-Host -NoNewLine -ForegroundColor White $Computer.ToLower()
      Write-Host -ForegroundColor Yellow " does not have a DNS record."
    }
  }
}
