Import-Module ActiveDirectory
Add-Type -Assembly System.Web
$users = @()
$apikey=$args[0]
$userString = ""
#$users = (Get-ADUser -Filter *).Name | Format-Table AutoSize | Out-String
#$users
 
function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs=""
    return [String]$characters[$random]
}
 
function Scramble-String([string]$inputString){     
    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}
 
function passchangeREG() {
   # $userlist = New-Object PSObject
    $userlist = @()
    $adGroupMemberList = Get-ADUser -Filter *
 
    foreach($user in $adGroupMemberList) {

        $password = "bruh12345!@#$%"
        $newPassword = $password
        $sam = ($user).SamAccountName
        #$users += [PSCustomObject]@{
        #	'Username' = $sam
        #	'Password' = $newPassword
        #}
        $users | Add-Member -MemberType NoteProperty -Name "Username" -Value $sam
        $users | Add-Member -MemberType NoteProperty -Name "Password" -Value $newPassword
        $userString += "$sam,$newPassword`n"
    }
 
        pointofnoreturn
}
 
function pointofnoreturn() {
    #making post
    #$bruh = $userlist -join "`n"
    #$newbruh = $bruh | Format-Table Autosize | Out-String
    $Filename = "asdf.csv"
    $userString > $Filename

    #$postParams =@{api_dev_key=$apikey;api_option='paste';api_paste_code="bruh";api_paste_expire_date="10M"}
    #$postParams
    #$response = Invoke-WebRequest -Uri 'https://pastebin.com/api/api_post.php' -Method Post -Body $postParams -OutVariable response
    Write-Host "PASTEBIN LINK FOR CSV:"
    #print pastebin URL
    #$response
 
	$continuebreak = Read-Host '
   	Passwords are waiting to be reset, continue? [y/n]
    '
    if($continuebreak -eq 'y' -Or $continuebreak -eq 'Y') {
    	foreach ($u in $users) {
    		Set-ADAccountPassword -Identity ($u).Username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText ($u).Password -Force)
    	}
    } else {
    	pointofnoreturn
    }
}
 
 
passchangeREG