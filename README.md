# Splunk ES Queries
This is a compilation of Splunk queries that I've collected and used over time. These can be used for threat hunting (e.g. Zerologon or lateral movement) or detecting suspicious behavior (e.g. a large number of failed logins in a short amount of time). I'll add to this list as I find more.

## Zerologon
```
index="your index name here" (sourcetype="<windows_sourcetype_security>" OR source="windows_source_security") EventCode="4742" OR EventCode="4624" AND (src_user="*anonymous*" OR member_id="*S-1-0*")
| eval local_system=mvindex(upper(split(user,"$")),0)
| search host=local_system
| table _time EventCode dest host ComputerName src_user Account_Name local_system user Security_ID member_id src_nt_domain dest_nt_domain
```
<br />

## Username guessing brute force attack
```
index="your index name here" sourcetype=windows EventCode=4625 OR EventCode=4624 
 | bin _time span=5m as minute 
 | rex "Security ID:\s*\w*\s*\w*\s*Account Name:\s*(?<username>.*)\s*Account Domain:" 
 | stats count(Keywords) as Attempts,
 count(eval(match(Keywords,"Audit Failure"))) as Failed,
 count(eval(match(Keywords,"Audit Success"))) as Success by minute username
 | where Failed>=4
 | stats dc(username) as Total by minute 
 | where Total>5
 ```
 <br />

## Successful file access (must have object access auditing enabled)
```
index="your index name here" sourcetype=WinEventLog (Relative_Target_Name!="\\""" Relative_Target_Name!="*.ini") user!="*$" | bucket span=1d _time | stats count by Relative_Target_Name, user, _time, status | rename _time as Day | convert ctime(Day)
```
<br />

## Successful Logons
```
index="your index name here" source="WinEventLog:security" EventCode=4624 Logon_Type IN (2,7,10,11) NOT user IN ("DWM-*", "UMFD-*")
| eval Workstation_Name=lower(Workstation_Name)
| eval host=lower(host)
| eval hammer=_time 
| bucket span=12h hammer 
| stats values(Logon_Type) as "Logon Type" count sparkline by user host, hammer, Workstation_Name
| rename hammer as "12 hour blocks" host as "Target Host" Workstation_Name as "Source Host"
| convert ctime("12 hour blocks")
| sort - "12 hour blocks"
```
<br />

## Failed Logons
```
index="your index name here" source="WinEventLog:security" EventCode=4625
| eval Workstation_Name=lower(Workstation_Name)
| eval host=lower(host) 
| eval hammer=_time 
| bucket span=5m hammer 
| stats count sparkline by user host, hammer, Workstation_Name
| rename hammer as "5 minute blocks" host as "Target Host" Workstation_Name as "Source Host"
| convert ctime("5 minute blocks")
```
<br />

## User Logon, Logoff, and Duration
```
index="your index name here" source="wineventlog:security" action=success Logon_Type=2 (EventCode=4624 OR EventCode=4634 OR EventCode=4779 OR EventCode=4800 OR EventCode=4801 OR EventCode=4802 OR EventCode=4803 OR EventCode=4804 ) user!="anonymous logon" user!="DWM-*" user!="UMFD-*" user!=SYSTEM user!=*$ (Logon_Type=2 OR Logon_Type=7 OR Logon_Type=10)
| convert timeformat="%a %B %d %Y" ctime(_time) AS Date 
| streamstats earliest(_time) AS login, latest(_time) AS logout by Date, host
| eval session_duration=logout-login 
| eval h=floor(session_duration/3600) 
| eval m=floor((session_duration-(h*3600))/60) 
| eval SessionDuration=h."h ".m."m " 
| convert timeformat=" %m/%d/%y - %I:%M %P" ctime(login) AS login 
| convert timeformat=" %m/%d/%y - %I:%M %P" ctime(logout) AS logout 
| stats count AS auth_event_count, earliest(login) as login, max(SessionDuration) AS sesion_duration, latest(logout) as logout, values(Logon_Type) AS logon_types by Date, host, user
```
<br />

## Timechart of the Status of a Locked Out Account
```
index="your index name here" sourcetype="WinEventLog:Security" EventCode=4625 AND Status=0xC0000234 
| timechart count by user 
| sort -count
```
<br />

## AD Password Change Attempts
```
index="your index name here" source="WinEventLog:Security" "EventCode=4723" src_user!="*$" src_user!="_svc_*" 
| eval daynumber=strftime(_time,"%Y-%m-%d") 
| chart count by daynumber, status 
| eval daynumber = mvindex(split(daynumber,"-"),2)
```
<br />

## PTH Detection
```
index="your index name here" ( EventCode=4624 Logon_Type=3 ) OR ( EventCode=4625 Logon_Type=3 ) Authentication_Package="NTLM" NOT Account_Domain=YOURDOMAIN NOT Account_Name="ANONYMOUS LOGON"
```
<br />

## Find Passwords Entered As Usernames
```
index="your index name here" source=WinEventLog:Security TaskCategory=Logon Keywords="Audit Failure" 
| eval password=if(match(User_Name, "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[\W])(?=.{10,})"), "Yes", "No") 
| stats count by password User_Name 
| search password=Yes
```
<br />

## Failed Attempt to Login To A Disabled Account
```
index="your index name here" source="WinEventLog:security" EventCode=4625 (Sub_Status="0xc0000072" OR Sub_Status="0xC0000072") Security_ID!="NULL SID" Account_Name!="*$" 
| eval Date=strftime(_time, "%Y/%m/%d")
| rex "Which\sLogon\sFailed:\s+\S+\s\S+\s+\S+\s+Account\sName:\s+(?<facct>\S+)" 
| eval Date=strftime(_time, "%Y/%m/%d") 
| stats count by Date, facct, host, Keywords 
| rename facct as "Target Account" host as "Host" Keywords as "Status" count as "Count"
 ```
<br />

## See when Windows Audit Logs are Cleared
```
index="your index name here" source=WinEventLog:security (EventCode=1102 OR EventCode=517) 
| eval Date=strftime(_time, "%Y/%m/%d") 
| stats count by Client_User_Name, host, index, Date 
| sort - Date 
| rename Client_User_Name as "Account Name"
```
<br />

## Failed RDP Attempt
```
index="your index name here" source=WinEventLog:Security sourcetype=WinEventLog:security Logon_Type=10 EventCode=4625 
| eval Date=strftime(_time, "%Y/%m/%d") 
| rex "Failed:\s+.*\s+Account\sName:\s+(?<TargetAccount>\S+)\s" 
| stats count by Date, TargetAccount, Failure_Reason, host 
| sort - Date
```
<br />

## Disabled Account Re-enabled
```
index="your index name here" sourcetype=WinEventLog:Security (EventCode=4722) 
| eval Date=strftime(_time, "%Y/%m/%d") 
|rex "ID:\s+\w+\\\(?<sourceaccount>\S+)\s+" 
| rex "Account:\s+Security\sID:\s+\w+\\\(?<targetaccount>\S+)\s+" 
| stats count by Date, sourceaccount, targetaccount, Keywords, host 
| rename sourceaccount as "Source Account" 
| rename targetaccount as "Target Account" 
| sort - Date
```
<br />

## Account Deleted within 24 hours of Creation
```
index="your index name here" sourcetype=WinEventLog:Security (EventCode=4726 OR EventCode=4720) 
| eval Date=strftime(_time, "%Y/%m/%d") 
| rex "Subject:\s+\w+\s\S+\s+\S+\s+\w+\s\w+:\s+(?<SourceAccount>\S+)" 
| rex "Target\s\w+:\s+\w+\s\w+:\s+\S+\s+\w+\s\w+:\s+(?<DeletedAccount>\S+)" 
| rex "New\s\w+:\s+\w+\s\w+:\s+\S+\s+\w+\s\w+:\s+(?<NewAccount>\S+)" 
| eval SuspectAccount=coalesce(DeletedAccount,NewAccount) 
| transaction SuspectAccount startswith="EventCode=4720" endswith="EventCode=4726" 
| eval duration=round(((duration/60)/60)/24, 2) 
| eval Age=case(duration<=1, "Critical", duration>1 AND duration<=7, "Warning", duration>7, "Normal")
| table Date, index, host, SourceAccount, SuspectAccount, duration, Age 
| rename duration as "Days Account was Active" 
| sort + "Days Account was Active"
```
<br />

## File Deletion Attempts
```
index="your index name here" sourcetype="WinEventLog:Security" EventCode=564 
| eval Date=strftime(_time, "%Y/%m/%d") 
| stats count by Date, Image_File_Name, Type, host 
| sort - Date
```
<br />

## New Service Installation on Windows
```
index="your index name here" sourcetype=WinEventLog:Security (EventCode=4697 OR EventCode=601) 
| eval Date=strftime(_time, "%Y/%m/%d") 
| eval Status=coalesce(Keywords,Type) 
| stats count by Date, Service_Name, Service_File_Name, Service_Account, host, Status
```
<br />

## Changes to Windows User Group by Account
```
index="your index name here" sourcetype=WinEventLog:Security (EventCode=4728 OR EventCode=4732 OR EventCode=4746 OR EventCode=4751 OR EventCode=4756 OR EventCode=4161 OR EventCode=4185) 
| eval Date=strftime(_time, "%Y/%m/%d") 
| rex "Member:\s+\w+\s\w+:.*\\\(?<TargetAccount>.*)" 
| rex "Account\sName:\s+(?<SourceAccount>.*)" 
| stats count by Date, TargetAccount, SourceAccount, Group_Name, host, Keywords 
| sort - Date 
| rename SourceAccount as "Administrator Account" 
| rename TargetAccount as "Target Account"
```
<br />

## Failed Authentication to Non-Existing Account
```
index="your index name here" source="WinEventLog:security" sourcetype="WinEventLog:Security" EventCode=4625 Sub_Status=0xC0000064 
| eval Date=strftime(_time, "%Y/%m/%d") 
| rex "Which\sLogon\sFailed:\s+Security\sID:\s+\S.*\s+\w+\s\w+\S\s.(?<uacct>\S.*)" 
| stats count by Date, uacct, host 
| rename count as "Attempts" 
| sort - Attempts
```
<br />

## Time Between Account Creation and Deletion
```
index="your index name here" sourcetype=WinEventLog:Security (EventCode=4726 OR EventCode=4720) 
| eval Date=strftime(_time, "%Y/%m/%d") 
| rex "Subject:\s+\w+\s\S+\s+\S+\s+\w+\s\w+:\s+(?<SourceAccount>\S+)" 
| rex "Target\s\w+:\s+\w+\s\w+:\s+\S+\s+\w+\s\w+:\s+(?<DeletedAccount>\S+)" 
| rex "New\s\w+:\s+\w+\s\w+:\s+\S+\s+\w+\s\w+:\s+(?<NewAccount>\S+)" 
| eval SuspectAccount=coalesce(DeletedAccount,NewAccount) 
| transaction SuspectAccount startswith="EventCode=4720" endswith="EventCode=4726" |eval duration=round(duration/60, 2) 
| eval Age=case(duration<=240, "Critical", duration>240 AND duration<=1440, "Warning", duration>1440, "Normal")
| table Date, index, host, SourceAccount, SuspectAccount, duration, Age 
| rename duration as "Minutes Account was Active" 
| rename index as "SSP or Index" 
| sort + "Minutes Account was Active"
```
<br />

## Weekend User Activity
```
index="your index name here" sourcetype="WinEventLog:Security" (date_wday=saturday OR date_wday=sunday) 
| stats count by Account_Name, date_wday
```
<br />

## Time Between Rights Granted and Revoked
```
index="your index name here" sourcetype=WinEventLog:Security (EventCode=4717 OR EventCode=4718) 
| rex "Access\sGranted:\s+Access\sRight:\s+(?\w+)"
| rex "Access\sRemoved:\s+Access\sRight:\s+(?\w+)"
| eval Rights=coalesce(RightGranted,RightRemoved) 
| eval status=case(EventCode=4717, "New Rights Granted by:", EventCode=4718, "Rights Removed by:")
| transaction Rights user startswith="Granted" endswith="Removed" 
| where duration > 0
| eval duration = duration/60 
| eval n=round(duration,2) 
| eval Date=strftime(_time, "%Y/%m/%d") 
| table Date, host, status, Security_ID, user, Rights, n 
| rename Security_ID as "Source Account" 
| rename user as "Target Account" 
| rename n as "Minutes between Rights Granted Then Removed" 
| sort - date
```
<br />

## Console Lock Duration
```
index="your index name here" sourcetype=WinEventLog:Security (EventCode=4800 OR EventCode=4801) 
| eval Date=strftime(_time, "%Y/%m/%d") 
| transaction host Account_Name startswith=EventCode=4800 endswith=EventCode=4801 
| eval duration = duration/60 
| eval duration=round(duration,2)
| table host, Account_Name, duration, Date 
| rename duration as "Console Lock Duration in Minutes" 
| sort - date
```
<br />

## Privilege Escalation Detection
```
index="your index name here" sourcetype="WinEventLog:Security" (EventCode=576 OR EventCode=4672 OR EventCode=577 OR EventCode=4673 OR EventCode=578 OR EventCode=4674) 
| stats count by user
```
<br />

## Number of Accounts Created in Windows Environment
```
index="your index name here" sourcetype=WinEventLog:Security (EventCode=624 OR EventCode=4720) 
| eval NewAccount=case(EventCode=624, "New Account Created", EventCode=4720, "New Account Created") 
| stats count(NewAccount) as creation 
| gauge creation 1 5 15 25
```
