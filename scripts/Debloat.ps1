$BloatwareList = @(
		"Microsoft.BingNews"
		"Microsoft.BingWeather"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		"Microsoft.MicrosoftOfficeHub"
		"Microsoft.MicrosoftSolitaireCollection"
		#"Microsoft.MicrosoftStickyNotes" / sysprep bug
		"Microsoft.PowerAutomateDesktop"
		"Microsoft.SecHealthUI"
		"Microsoft.People"
		"Microsoft.Todos"
		#"Microsoft.Windows.Photos" valakinek lehet fontos
		"Microsoft.WindowsAlarms"
		"Microsoft.WindowsCamera"
		"microsoft.windowscommunicationsapps"
		"Microsoft.WindowsFeedbackHub"
		"Microsoft.WindowsMaps"
		"Microsoft.WindowsSoundRecorder"
		"Microsoft.YourPhone"
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo"
		"MicrosoftTeams"
	)
	foreach ($Bloat in $BloatwareList)
	{
		if ((Get-AppxPackage -Name $Bloat).NonRemovable -eq $false)
		{
			$Log.Text = "Removing $Bloat"
			Try
			{
				Get-AppxPackage -Name $Bloat | Remove-AppxPackage -ErrorAction Stop | Out-Null
				Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
			}
			Catch
			{
				$Log.Text = "Failed to remove $Bloat, exception : $($_)"
			}
			
		}
	}