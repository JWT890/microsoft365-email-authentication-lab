# email-security-lab

Email security is vital for making sure emails are coming from the right place and good senders based off secure settings. SPF makes sure which mail servers are authorized, DKIM adds a signature so that systems can validate the domain's public key, while DMARC makes sure both are aligned and specifies how each one should handle failures and reporting. 

# Setup
After setting up a Microsoft 365 domain, go to Settings -> Domains and get here:    
![Domain](./images/domain.png)  
And you will be greeted by the add a domain screen, so I'll put jon-myemaillab and click on use this domain:    
![Email](./images/email.png)    
And make sure to add a .com at the end and click on use this domain. Then on the next screen:   
![Verify](./images/verify.png)  
Click on the first option for adding a .TXT option and reach the add a record to verify ownership screen and save the TXT name, value and TTL for freeDNS.  
Then go to freeDNS here: https://freedns.afraid.org/menu/   
And click on subdomains -> Add a Subdomain and get here:    
![Record](./images/record.png)  
Change the type to text, enter in the subdomain details and change the domain, enter the destination as the MS value in "" and enter the codes but I usually reach this:    
![Fail](./images/fail.png)  
So lets go buy a domain from Cloudflare and look for a .com or .org and buy it. After buying, click on manage and go to DNS records/configurations to verify:   
![DNS](./images/dns.png)    
Then go back to Settings -> Domains in 365 and click on add domain and enter the domain that was bought and get here:   
![Verify](./images/verify1.png) 
Since it detects cloudflare the auto method is available but lets click on different options to add a TXT record and hit continue and reach the add a record to verify ownership screen and copy it and go to Cloudflare and click on add record.   
In add record, set the type to TXT, for name type @, and for content put the MS=text that was generated and click on save. 
Then in a command prompt type nslookup -type=TXT jon-maillab.org to see the MS pop up.  
Then go back to 365 and click on verify:    
![Connect](./images/connect.png)    
Choose the Add your own DNS option and get to the Add DNS records screen and since I don't have the Business Basic Standard trial I'll have to get the trial for it to use Exchange so hit continue and add. Shortly after doing this I got the trial. Then assign the license to the admin user and create 2 users with the domain bought and the licenses.    
![Users](./images/users.png)    
And with license added, go back to Settings -> Domains and click on the Cloudflare domain and when doing adding the DNS option, the Exchange information will pop up and finish the setup for it and it should say healthy. 
Then in Cloudflare for DNS, add several DNS records for information that was created for Exchange and enter it into Cloudflare with the first one as an MX with the MS valeu, second as a TXT with the v=spf info, third as CNAME with it named autodiscover with the content of autodiscover.outlook.com, and the fourth one named as _dmarc with the content having v=DMARC1; p=none rua=mailto:alice@jonmaillab.org; fo=1 and then do nslookups on them all to verify by typing: 
nslookup -type-MX jon-maillab.org 1.1.1.1   
nslookup -type=TXT jon-maillab.org 1.1.1.1
nslookup -type=TXT _dmarc.jon-maillab.org 1.1.1.1   
nslookup -type-MX jon-maillab.org 1.1.1.1   
nslookup -type=CNAME autodiscover.jon-maillab.org 1.1.1.1   
Then go to one of the user accounts, create a password for it, then sign into it, set up MFA and get into email like so:    
![Outlook](./images/outlook.png)    
Then I'll send a test message to my email and get it to send to myself. After sending:  
![Sent](./images/sent.png)  
Then in Gmail, click on the three dots in the right corner and click on show original.  
![Email1](./images/01-baseline-all-pass-redacted.png)   
Then I sent a reply to Alice by saying hello i think and the report came a few hours later: 
![Report](./images/02-dmarc-report-google-redacted.png) 
And this can also be seen in the dmarc report section. From looking over it seems that a few edits must be made since DKIM shows as failed since SPF and DMARC passed with no DKIM signature yet. So go to Microsoft Defender -> Email & Collaboration -> Policies & rules -> Threat Policies -> Email Authentication settings -> DKIM and see that it faild to load. Did some troubleshooting and what occured with Claude: 
1. Environment
Item	Choice
Domain	jon-maillab.org (registered at Cloudflare Registrar)
DNS host	Cloudflare (free plan), all mail records set to DNS only
Mail platform	Microsoft 365 Business Standard trial (Exchange Online)
Test mailboxes	alice@ and bob@jon-maillab.org, plus an external Gmail account

Setup problems I hit (and what I did)

Free domain failed. FreeDNS blocks MS= verification records on its shared public domains, and the record that saved had lost its MS= prefix. I confirmed this from the error message and the mismatch between what I entered and what was stored, then switched to a registered domain.
No Exchange license. The "Add DNS records" step had no Exchange option. The leftover trial only had Entra ID P2 and Intune, neither of which includes a mailbox. I added Business Standard and assigned licenses to both users.
2. DNS records
nslookup -type=TXT jon-maillab.org 1.1.1.1  
nslookup -type=MX jon-maillab.org 1.1.1.1   
nslookup -type=TXT _dmarc.jon-maillab.org 1.1.1.1   
nslookup -type=CNAME autodiscover.jon-maillab.org 1.1.1.1   
Type	Name	Value
TXT	@	MS=ms######## (domain verification) 
MX	@	jon-maillab-org.mail.protection.outlook.com, priority 0 
TXT	@	v=spf1 include:spf.protection.outlook.com -all  
CNAME	autodiscover	autodiscover.outlook.com    
TXT	_dmarc	v=DMARC1; p=none; rua=mailto:alice@jon-maillab.org; fo=1    

DMARC starts at p=none (monitor only) so I could collect reports before enforcing.  

3. Baseline test (before DKIM)

I sent a message from Alice to Gmail and read the header under Show original.   
Which shows here or just scroll above:  
![Show](./images/01-baseline-all-pass-redacted.png)    
The SPF and DMARC both pass with no DKIM signature. 
A correction worth noting: I first read this header as "DKIM passes", because an ARC-Authentication-Results line contained dkim=pass. That line is Microsoft's own evaluation at its hop, preserved by ARC. It is not Google's check of a DKIM signature. The DMARC report below showed dkim=fail, which I cross-checked against the header to find the mistake. Lesson: use the receiving server's own Authentication-Results line, and confirm with a second source.  

4. First DMARC aggregate report (Google)

A report arrived about a few hours after the first test messages. Which can be seen by scrolling up or here:    
![Report](./images/02-dmarc-report-google-redacted.png) 
Field	Value	Meaning
Reporter	google.com	Receiving provider
Window	2026-10-20 00:00 to 23:59 UTC	24-hour period
Published policy	p=none, sp=none, pct=100, relaxed alignment	What Google saw in _dmarc
Source	Microsoft outbound IPv6 (redacted)	Sending server
Count	1	Messages from that source
Disposition	none	No action at p=none
DKIM / SPF	fail / pass	Aligned results used for DMARC

DMARC needs either SPF or DKIM to pass and align, so one pass is enough. That is also the weakness here. Forwarding breaks SPF, which would leave the domain with no passing mechanism. DKIM needed to be enabled.

5. Enabling DKIM

The Defender portal DKIM page (Email & collaboration, Policies & rules, Threat policies, Email authentication settings, DKIM) returned "Failed to load data", including in a private window. Accepted domains in the Exchange admin center showed jon-maillab.org as authoritative, so Exchange itself was healthy. I configured DKIM through Exchange Online PowerShell instead.   
Connect

powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser    # module failed to load until this was set
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName ADMIN@<tenant>.onmicrosoft.com

Check for an existing config. It returned "object couldn't be found", so no DKIM config existed for the domain.

powershell
Get-DkimSigningConfig -Identity jon-maillab.org | Format-List Domain,Enabled,Selector1CNAME,Selector2CNAME

Create the config (disabled) and read the selector targets

powershell
New-DkimSigningConfig -DomainName jon-maillab.org -Enabled $false
Get-DkimSigningConfig -Identity jon-maillab.org | Format-List Selector1CNAME,Selector2CNAME

Publish two CNAMEs in Cloudflare (DNS only)

Name	Target
selector1._domainkey	value of Selector1CNAME
selector2._domainkey	value of Selector2CNAME
nslookup -type=CNAME selector1._domainkey.jon-maillab.org 1.1.1.1
nslookup -type=CNAME selector2._domainkey.jon-maillab.org 1.1.1.1

Current targets end in .dkim.mail.microsoft. Older documentation shows .onmicrosoft.com, so always copy the values from Get-DkimSigningConfig.

Enable signing, retrying while Microsoft syncs

powershell
1..12 | ForEach-Object {
  try {
    Set-DkimSigningConfig -Identity jon-maillab.org -Enabled $true -ErrorAction Stop
    Write-Host "Enabled"; break
  } catch {
    Write-Host "Not yet ($_)"; Start-Sleep -Seconds 300
  }
}
Get-DkimSigningConfig -Identity jon-maillab.org | Format-List Domain,Enabled,Status

Result: Enabled : True, Status : Valid.

6. Troubleshooting notes from the DKIM work
Symptom	Root cause	Fix
Connect-ExchangeOnline found the module but could not load it	PowerShell execution policy	Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
DKIM CNAMEs resolved to the literal text selector1cname	I pasted the property name instead of the value from the PowerShell output	Edited both records with the real targets, then re-ran nslookup
Cloudflare rejected the target with "Content for CNAME record is invalid"	The Target field still held the label text Selector1CNAME :	Replaced it with only the value after the colon
Set-DkimSigningConfig failed with "CNAME record does not exist" even though nslookup showed correct records	Microsoft's backend had not synced yet. The error lists the same two records I had published	Waited and retried on a loop. It succeeded on the second attempt, about 5 minutes later

The records were correct from the start of the sync delay. I verified this by comparing the targets in Microsoft's error message against my nslookup output character for character, instead of assuming a DNS fault.   
Then I sent a email from Alice to my again and saw this after clicking on the three dots:   
![Enabled](./images/03-dkim-enabled-pass-redacted.png)  
Now it shows DKIM as working with a PASS for DKIM. From Alice, I sent emails to my other outlook emails and a secondary Gmail email as well.    
![Outlook](./images/04-outlook-com-pass-redacted.png)   
Second Gmail:   
![Gmail](./images/05-second-gmail-pass-redacted.png)    
Internal:   
![Internal](./images/06-internal-unsigned-redacted.png) 
With those emails sent and data gotten, its time to go and run a Message trace in Exchange by going to Mail-Flow -> Message trace and see this: 
![Trace](./images/trace.png)    
Click on Start a Trace and set the sender to alice@jon-maillist.org with a time range of the past couple days to see the messages sent: 
![Result](./images/result.png)  
And from checking the Alice to an external address: 
![Details](./images/07-message-trace-external-redacted.png) 
And from checking the Alice to Bob address: 
![Detail1](./images/08-message-trace-internal-redacted.png) 
From looking over both is that it needed to confirm a test message from tenant to an outside source. Trace timestamps match up from when i sent them out. Key finding is that external mail ends at Send external with internal ending at Deliver. Takeaway is that trace confirms the handoff with recipient headers confirm authentication and arrival.   
When looking over the DMARC report from yesterday:  
![Result1](./images/09-dmarc-report-google-day2-redacted.png) 
Comparing this to the first DMARC report, DKIM now passes the test and aligned with the domain with everything being legit and no unauthorized sources. Shows that the DKIM is working and functional.  
AFter waiting a day or so, the aggregator shows this: 
![Result2](./images/10-dmarc-report-outlook-redacted.png) 
One message from Microsoft's outbound infrastructure to another outlook account with SPF pass, from, DKIM for selector1 and no disposition. Matched header at send time with Microsoft's report format adds envelope_to, envelope_From, and SPF scope which Google doesn't have.  

# SPF Failure Test 
First lets start by running nslookup -type=TXT jon-maillab.org 1.1.1.1 and should include the line v=spfl include:spf.protection.outlook.com -all.  
Then go into Cloudflare and edit the TXT record with spfl in it to just v=spf1 -all. After saving, wait a few minutes and run:  
nslookup -type=TXT jon-maillab.org 1.1.1.1 and nslookup -type=TXT jon-maillab.org 8.8.8.8 which should show as blanks.  
Then send an email in Outlook after this change, with the email titled SPF break test and send it.  
![Result3](./images/11-spf-fail-dmarc-pass-redacted.png)  
With the change to v=spf1 -all, it shows that spf failed and when fixed back in Cloudflare: 
![Result4](./images/12-spf-restored-pass-redacted.png)  
The fix should also be seen when running nslookup -type=TXT jon-maillab.org 1.1.1.1 with v=spfl restored. 

# DKIM break test
For this, something to remember is that if CNAME disappers, those that receive emails will still see a signature but no key. Before breaking run nslookup -type=CNAME selector1._domainkey.jon-maillab.org 1.1.1.1 which will show the selector1 and domain key for the domain. 
Then go into into Cloudflare and delete the selecto1 key. Then after a few minutes run: 
nslookup -type=CNAME selector1._domainkey.jon-maillab.org 1.1.1.1 
nslookup -type=CNAME selector1._domainkey.jon-maillab.org 8.8.8.8 
In which the output should say that 1.1.1.1 and dns.google can't find selector1 and that its non-existent.  
Then send an email from Alice with the subject of DKIM break test:  
![Result5](./images/13-dkim-break-redacted.png) 
Then re-add the selector1 part back into Cloudflare and after readding since the root cause was the selector1 CNAME being deleted: 
![Result6](./images/14-dkim-after-restore-redacted.png) 
Something to see is that it says Fail for DKIM. Probably best to wait a few minutes before retrying.  
After retrying from Alice:  
![Result7](./images/16-dkim-retest-pass-redacted.png) 
With this one of the key lookup error, it was caused by some cache i guess or just took a few minutes and I didn't wait for it to reset for a few minutes.
After looking at the DMARC report from this morning:  
![Result8](./images/17a-dmarc-report-oct27-part1-redacted.png)  
![Result9](./images/17b-dmarc-report-oct27-part2-redacted.png)  
![Result10](./images/17c-dmarc-report-oct27-part3-redacted.png) 
These three pictures show the messages that were sent with at least one pass that is aligned and each failure appears. 

# Spoof test
Start off by running Test-NetConnection gmail-smtp-in.1.google.com -Port 25 which should show the tcp side failed but ping worked. Solution was to turn phone hotspot on and run it again:  
![Result11](./images/18-port25-open-hotspot-redacted.png) 
Something to also do before the test is to create an account with SMTP2GO to make things easier. I created an account with the alice email and was able to get signed in. 
Then go to Sending -> SMTP Users and get here:  
![SMTP](./images/smtp.png)  
Click on continue and click on create SMTP user, jot down the username and password and hit add SMTP user. Then to add alice, go to Sending -> Verified Senders like so:  
![Sender](./images/sender.png)  
And click on single sender emails, type in the Alice email to send a verify email.  
![Verify2](./images/verify2.png)  
Then once that is set, in a terminal or Visual Studio code run after getting the user and password: 
export SMTP250="user"
export SMTP250="password" 
export MY_GMAIL="gmail" 
And then run to see if it was set:  
echo ${SMTP2GO_USER:+set} ${SMTP2GO_PASS:+set} ${MY_GMAIL:+set} and run the spoof_test.py script and hope to see it run without error by seeing code 250 which should bring this email in both: 
![Lab](./images/lab.png)  
And in Gmail: 
![Result12](./images/gmail_headers_redacted.png)  
And for Outlook:  
![Outlook1](./images/bob_headers_redacted.png)  
What this shows is that a policy might be set up for honoring DMARC records and only acts when the policy is set to p=quarantine or reject so its most likely set to p=none

Next test will be to test with quarantine.  
First is to check Bob's inbox for the email that was sent over there and check the details for it from this:  
![Result13](./images/21-bob-antispam-report-redacted.png) 
What occured with this is that it marked dmarc as fail, recorded a 601 error that can be seen earlier, has a compauth=fail and this means the failure was recorded but not enforced since p=none requests no action and Microsoft's spoof detection did not categorize it. Usualy what 601 means is that the sending domain is accepted within the organization as self-to-self as intra-org spoofing.  
The fix to enforce the quarantine is to edit the _dmarc TXT record in Cloudflare to include p=quarantine instead of p=none, save it and wait for a few minutes. 
After a few minutes run nslookup -type=TXT _dmarc.jon-maillab.org 1.1.1.1 and see the p=quarantine is in the output.  
Then in spoof_test.py change the subject line to: Unauthorized sender test 2 (quarantine) and run python spoof_test.py. 
First go check Gmail to see if it pops up in junk/spam: 
![Gmail](./images/gmail.png)  
And after checking the email shows this:  
![Test2](./images/test2_quarantine_gmail_headers_redacted.png)  
From this image after running the script it shows SPF and DKIM as still passing but DMARC still fails. So send a email from Alice to Gmail and get this result: 
![Sent](./images/alice_to_gmail_dmarc_pass_redacted.png)  
From this screenshot, it has p=Quarantine on it and is aligned with SPF. Since Bob's side hasn't been done yet or checked. Go to Defender -> Email & Collaboration -> Exchange Message Trace and click on Start a Trace with the alice email as the sender and bob as the recipient with a date time range of today, Halloween, and UTC time of 17:00 and 18:00 and hit search and notice this: 
![Check](./images/check.png)  
This shows the image was quarintined and is marked as not yet delievered. To see further click on the quarantine link and get here: 
![Defender](./images/defender.png)  
And after clicking on it: 
![Detail](./images/detail.png)  
What can be seen from looking at the above image is that the reason for the quarantine is because of phishing with the detection logic saying the DMARC is spoofed and only allows one per policy.  

Next test is to do p=reject in Cloudflare.  
With the next test, go the _dmarc in Cloudflare and change the p= to p=reject and add pct=100 and save it then run two nslookups: 
nslookup -type=TXT _dmarc.jon-maillab.org 1.1.1.1 
nslookup -type=TXT _dmarc.jon-maillab.org 8.8.8.8 
And see the changes of p=reject and pct=100 
Then in the spoof_test.py, change the subject to Unauthorized sender test 3 (reject) and run with python spoof_test.py. After running, check the gmail that was used in spam and see no updated email sent, along with both Outlook emails. First thing to check would be the SMTP2GO side by going to Reports -> Activity and see the results: 
![Log](./images/log.png)  
Then click on the top email one and see this: 
![Result14](./images/test3_reject_gmail_smtp2go_redacted.png) 
This shows that SMTP2GO processed it around 3:30:35 PM and the next second was blocked with the message saying that mail from the email listed is not accepted. 
Then go to message trace and check the newer entries: 
![Reject](./images/reject.png)  
And 
![Reject1](./images/test3_reject_ndr_redacted.png)  
From looking over both, the one with bob as the receiver shows that access was denied and not sent because of the policy was that edited in Cloudflare. 
Then go back to the _dmarc policy in Cloudlare and edit it back to p=quarantine. After changing it back run once again to verify: 
nslookup -type=TXT _dmarc.jon-maillab.org 1.1.1.1 
nslookup -type=TXT _dmarc.jon-maillab.org 8.8.8.8 
After verifying it says quarantine, its time to go to Alice and send a email to the gmail to test if it works now.  
