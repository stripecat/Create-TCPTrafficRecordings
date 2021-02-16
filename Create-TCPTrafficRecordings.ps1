#requires -version 3
<#
.SYNOPSIS
  Windows system network activity recorder.
.DESCRIPTION
  Gets Windows TCP-connections and logs them to disk. Will not log UDP-connections at this time. IPV6 is supported.
.PARAMETER None
  No parameters exists.
.INPUTS
  None
.OUTPUTS
  Stdout
.NOTES
  Version:        1.0.0
  Author:         Erik Zalitis at Nordlo Improve AB <erik.zalitis@nordlo.com>
  Creation Date:  2021-02-16
  Purpose/Change: First version. It's free and so are the bugs.
  
.EXAMPLE
  Create-TCPTrafficRecordings - runs this program.
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Stop
$ErrorActionPreference = "Stop"
$currpath=(Get-Location).Path.tostring()
$file=$currpath + "\TCP-Connections-" + (Get-Date -format "yyyyMMdd-HHmm") + ".csv"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$DevScanInterval=10 # Seconds to wait between each scanning. Minimum value=3. Recommended value: 60.
$debug=0 # Debug = 1 means some extra texts will be displayed. Debug = 2 means ALL extra text will be show.
$logLPORT=1 # Log the local ports. Should be done, unless you just want information on how which firewall rules you need. !!! NOT IMPLEMENTED - Local ports will always be logged !!!

#-----------------------------------------------------------[Functions]------------------------------------------------------------


if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "[WARNING] Insufficient permissions to run this script with all features enabled. Some data will be missing. Open the PowerShell console as an administrator and run this script again to get full data."
$isadmin=0
}
else {
    Write-Host "Script is running as an administrator, all fields will be populated."
$isadmin=1
}

$lastexecution=(Get-Date).AddHours(-24)
$TimeElapsed=NEW-TIMESPAN –Start $lastexecution –End (get-date)


$myips=Get-NetIPAddress|foreach { $_.IPAddress } # We must know all the ips of this system in order to filter out connections from the system to itself.

$lsdate=(Get-Date -format "yyyy-MM-dd HH:mm:ss") # Yup. European date format. Feel free to change, but be careful when using as a file name.

$myitems=""

$myitems = @([pscustomobject]@{direction="None";LocalAddress="" + "127.0.0.1" + "";LocalPort=""  + "1"  + "";RemoteAddress="" + "127.0.0.1"  + ""; RemotePort="" + "1"  + ""; OwningProcessName="" + "Time when this script started." + ""; OwningProcess="" + 0 + "";OwningProcessUserName="" + "None" + "";OwningProcessFilePath="" + "OwningProcessFilePath" + "";LastSeen="" + $lsdate + ""})


Write-host "Now running"

Do
{

if ($TimeElapsed.totalseconds -lt $DevScanInterval)
{ 
    if ($debug -eq 2) {  Write-host "Waiting for time to pass. Elapsed so far: " + $TimeElapsed + " hours" }
    Start-Sleep 2 # Throttle the intervals.
    $TimeElapsed=NEW-TIMESPAN –Start $lastexecution –End (get-date)
    }
else
{
    $lastexecution=Get-Date
    if ($debug -eq 1) { Write-host "Time to execute the agent device update" }
    $TimeElapsed=NEW-TIMESPAN –Start $lastexecution –End (get-date)
    $lsdate=(Get-Date -format "yyyy-MM-dd HH:mm:ss")

    $connections=Get-NetTCPConnection -State Established

    Foreach ($connection in $connections)
    {

        # Create a tuple like "lip:lport:dip:dport"

       if (($myips -contains $connection.LocalAddress.tostring()) -and ($myips -contains $connection.RemoteAddress.tostring()))
       {
                              if ($debug -eq 2) {  Write-host "Connections between this computer and itself will not be saved." }
       }
       else
       {
            $direction = ""
            if ($connection.RemotePort -ge 49152) { $direction = "Incoming" } else { $direction = "Outgoing" } # In Windows the default source port range is now 49152 and higher. This is true for Linux as well. https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/default-dynamic-port-range-tcpip-chang

            # Check if the tuple already exists

            # if it does, update the LastSeen timestamp

            if ($myitems.LocalAddress -contains $connection.LocalAddress.tostring() -and $myitems.LocalPort -contains $connection.LocalPort.tostring() -and $myitems.RemoteAddress -contains $connection.RemoteAddress.tostring() -and $myitems.RemotePort -contains $connection.RemotePort.tostring())
            { 

                              if ($debug -eq 2) {  Write-host "It's a duplicate!" }

                $ErrorActionPreference = "Stop"

                try
                {
                    $rec=$myitems | where {$_.LocalAddress -eq $connection.LocalAddress.tostring() -and $_.LocalPort -eq $connection.LocalPort.tostring() -and $_.RemoteAddress -eq $connection.RemoteAddress.tostring() -and $_.RemotePort -eq $connection.RemotePort.tostring() -and $_.OwningProcess -eq $connection.OwningProcess.tostring()}
                    $rec.LastSeen=(Get-Date -format "yyyy-MM-dd HH:mm:ss")
                    if ($debug -eq 2) { "New count " + $myitems.count }
                }
                catch
                {
                    if ($debug -eq 2) { Write-Warning "Could not set new time stamp" }
                }
            }
            else
            {
      
            # if not, add it as a new entry.

            if ($debug -eq 1) { Write-host "Adding one new" }

            if ($isadmin -eq 1)
            {
                Try
                {
                    if ($debug -eq 2) { Write-Host "Getting process information for " + $connection.OwningProcess + "." }
                    $procid=(Get-Process -id $connection.OwningProcess -IncludeUserName)
                    $OwningProcessName=$procid.ProcessName
                    $OwningProcessUserName=$procid.UserName
                    $OwningProcessFilePath=$procid.Path
                }
                catch
                {
                    Write-Warning ("Could not get process id for process " + $connection.OwningProcess + ".")
                    $OwningProcessName="Unknown"
                    $OwningProcessUserName="Unknown"
                    $OwningProcessFilePath="Unknown"
                }
            }
            else
            {
                # If we're not running as admin, it's impossible to get the process data. So we just put empty data in there.
                $OwningProcessName="Unknown"
                $OwningProcessUserName="Unknown"
                $OwningProcessFilePath="Unknown"
            }
           
            $myitems +=
            @([pscustomobject]@{direction="" + $direction + "";LocalAddress="" + $connection.LocalAddress.tostring() + "";LocalPort=""  + $connection.LocalPort.tostring()  + "";RemotePort="" + $connection.RemotePort.tostring()  + "";RemoteAddress="" + $connection.RemoteAddress.tostring()  + ""; OwningProcess="" + $connection.OwningProcess + ""; OwningProcessName="" + $OwningProcessName + "";OwningProcessUserName="" + $OwningProcessUserName + "";OwningProcessFilePath="" + $OwningProcessFilePath + "";LastSeen="" + $lsdate + ""})
            }
        }
    }

if ($debug -eq 1) { "Done. Going back to sleep" }

# Write the data to the CSV

if ($debug -eq 1) { "Saving data to disk" }

$ErrorActionPreference = "Stop"
Try
{
    $myitems|export-csv -path $file -NoTypeInformation
    }
    catch
    {
        Write-Error ("[ERROR] Unable to save the data file. Given EC: " + $_ + ".")
    }
}

    } while ($true) # End main do loop