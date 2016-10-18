<#
.SYNOPSIS
    POC-Environment-Setup.ps1 - Script that configures the PoC environment for Azure Fast Start for IaaS.
.DESCRIPTION
    POC-Environment-Setup.ps1 - Script that configures the PoC environment for Azure Fast Start for IaaS.
	This script configures all necessary resources to have an environment that is spread between two locations, East and West.
	West location contains a domain controller and a virtual network, East location contains two IIS servers that are domain joined
	to Contosoad.com domain. East also has a virtual network, both of them are connected through a Vnet-to-Vnet VPN to allow 
	communication between them. IIS servers are also load balanced. Powershell DSC (Desired State Configuration) is used to
	configure the new Active Directory Forest and IIS servers. Three resource groups are created, one for east resources, one for
	west resources and the third one located in east for the storage accounts.
.DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.
    THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
    INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  
    We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object
    code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software
    product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the
    Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims
    or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
    Please note: None of the conditions outlined in the disclaimer above will supersede the terms and conditions contained
    within the Premier Customer Services Description.
#>
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

#----------------------------------------------------------------------------------------------------------------------
# Functions
#----------------------------------------------------------------------------------------------------------------------
function Create-DSCPackage
{
	param
	(
		[string]$dscScriptsFolder,
		[string]$outputPackageFolder,
		[string]$dscConfigFile
	)
    # Create DSC configuration archive
    if (Test-Path $dscScriptsFolder) {
        Add-Type -Assembly System.IO.Compression.FileSystem
        $ArchiveFile = Join-Path $outputPackageFolder "$dscConfigFile.zip"
        Remove-Item -Path $ArchiveFile -ErrorAction SilentlyContinue
        [System.IO.Compression.ZipFile]::CreateFromDirectory($dscScriptsFolder, $ArchiveFile)
    }
	else
	{
		thrown "DSC path $dscScriptsFolder does not exist"
	}
}

function Upload-BlobFile
{
    param
    (
        [string]$ResourceGroupName,
        [string]$storageAccountName,
        [string]$containerName,
        [string]$fullFileName
    )
 
    # Checks if source file exists
    if (!(Test-Path $fullFileName))
    {
        throw "File $fullFileName does not exist."
    }

    $storageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName 
   
    if ($storageAccount -ne $null)
    {
        # Create container
        New-AzureStorageContainer -Name $containerName -Context $storageAccount.Context -Permission Container -ErrorAction SilentlyContinue

        # Uploads a file
        $blobName = [System.IO.Path]::GetFileName($fullFileName)

        Set-AzureStorageBlobContent -File $fullFileName -Blob $BlobName -Container $containerName -Context $storageAccount.Context -Force
    }
    else
    {
        throw "Storage Account $storageAccountName could not be found at resource group named $ResourceGroupName"
    }
}

function Invoke-AzureRmPowershellDSCAD
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$OutputPackageFolder,

        [Parameter(Mandatory=$true)]
        [string]$DscScriptsFolder,

        [Parameter(Mandatory=$true)]
        [string]$DscConfigFile,

        [Parameter(Mandatory=$true)]
        [string]$DscConfigFunction,

        [Parameter(Mandatory=$false)]
        [string]$dscConfigDataFile,

        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [string]$StagingSaName,

        [Parameter(Mandatory=$true)]
        [string]$stagingSaResourceGroupName,

        [Parameter(Mandatory=$false)]
        [PSCredential]$Credentials
    )
    
    $outputPackagePath = Join-Path $outputPackageFolder "$dscConfigFile.zip"
    $configurationPath = Join-Path $dscScriptsFolder $dscConfigFile
    $configurationDataPath = Join-Path $dscScriptsFolder $dscConfigDataFile

    # Create DSC configuration archive
	Create-DSCPackage -dscScriptsFolder $dscScriptsFolder -outputPackageFolder $outputPackageFolder -dscConfigFile $dscConfigFile

    # Uploading DSC configuration archive
    Upload-BlobFile -storageAccountName $StagingSaName -ResourceGroupName $stagingSaResourceGroupName -containerName "windows-powershell-dsc" -fullFileName $outputPackagePath
	
	##
    ## In order to know current extension version, you can use the following cmdlet to obatin it (user must be co-admin of the subscription and a subscription in ASM mode must be set as default)
    ## $dscExt = Get-AzureVMAvailableExtension -ExtensionName DSC -Publisher Microsoft.Powershell
	##

    # Executing Powershell DSC Extension on VM
    Set-AzureRmVMDscExtension   -ResourceGroupName $ResourceGroupName `
                                -VMName $vmName `
                                -ArchiveBlobName "$dscConfigFile.zip" `
                                -ArchiveStorageAccountName $stagingSaName `
                                -ArchiveResourceGroupName $stagingSaResourceGroupName `
                                -ConfigurationData $ConfigurationDataPath `
                                -ConfigurationName $dscConfigFunction `
                                -ConfigurationArgument @{"DomainAdminCredentials"=$Credentials} `
                                -Version "2.1" `
                                -AutoUpdate -Force -Verbose
} 

function Invoke-AzureRmPowershellDSCIIS
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$OutputPackageFolder,

        [Parameter(Mandatory=$true)]
        [string]$DscScriptsFolder,

        [Parameter(Mandatory=$true)]
        [string]$DscConfigFile,

        [Parameter(Mandatory=$true)]
        [string]$DscConfigFunction,

        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [string]$StagingSaName,

        [Parameter(Mandatory=$true)]
        [string]$stagingSaResourceGroupName
    )
    
    $outputPackagePath = Join-Path $outputPackageFolder "$dscConfigFile.zip"
    $configurationPath = Join-Path $dscScriptsFolder  $dscConfigFile
    $configurationDataPath = Join-Path $dscScriptsFolder $dscConfigDataFile

    # Create DSC configuration archive
	Create-DSCPackage -dscScriptsFolder $dscScriptsFolder -outputPackageFolder $outputPackageFolder -dscConfigFile $dscConfigFile

    # Uploading DSC configuration archive
    Upload-BlobFile -storageAccountName $StagingSaName -ResourceGroupName $stagingSaResourceGroupName -containerName "windows-powershell-dsc" -fullFileName $outputPackagePath 

	##
    ## In order to know current extension version, you can use the following cmdlet to obatin it (user must be co-admin of the subscription and a subscription in ASM mode must be set as default)
    ## $dscExt = Get-AzureVMAvailableExtension -ExtensionName DSC -Publisher Microsoft.Powershell
	##

    # Executing Powershell DSC Extension on VM
	Set-AzureRmVMDscExtension   -ResourceGroupName $ResourceGroupName `
                                    -VMName $vmName `
                                    -ArchiveBlobName "$dscConfigFile.zip" `
                                    -ArchiveStorageAccountName $stagingSaName `
                                    -ArchiveResourceGroupName $stagingSaResourceGroupName `
                                    -ConfigurationName $dscConfigFunction `
                                    -Version "2.1" `
                                    -AutoUpdate -Force -Verbose
} 

#----------------------------------------------------------------------------------------------------------------------
# Script Start
#----------------------------------------------------------------------------------------------------------------------

# Authenticate to Azure and select a subscription
Add-AzureRmAccount
$subscriptionName = "<subscription name here>"
Select-AzureRmSubscription -SubscriptionName $subscriptionName


##
## How to obtain Azure Powershell Module Version 
## Get-Module -ListAvailable -Name Azure
##
## How to get a list of subscriptions you have access
## Get-AzureRmSubscription
##

# Location Definition
$westLocation = "westus"
$eastLocation = "eastus"

# Resource Group Creation
Write-Verbose "Creating resource groups" -Verbose
$rgWest = New-AzureRmResourceGroup -Name "poc-west-rg" -Location $westLocation
$rgEast = New-AzureRmResourceGroup -Name "poc-east-rg" -Location $eastLocation
$rgStorage = New-AzureRmResourceGroup -Name "poc-storage-rg" -Location $eastLocation

##
## How to get a resource group if needed
## $rgWest = Get-AzureRmResourceGroup -Name "poc-west-rg" -Location $westLocation
## $rgEast = Get-AzureRmResourceGroup -Name "poc-east-rg" -Location $eastLocation
## $rgStorage = Get-AzureRmResourceGroup -Name "poc-storage-rg" -Location $eastLocation
##

#----------------------------------------------------------------------------------------------------------------------
# Virtual networks section - including Subnets, Vnets, Vnet-to-Vnet VPN, load balancer and basic Network security Group
#----------------------------------------------------------------------------------------------------------------------

### Start of Virtual Networks Section

# Subnet Creation
Write-Verbose "Creating Subnets..." -Verbose

# Subnets belonging to West Location
$gwSNNameWest = "GatewaySubnet"
$gwSNWest = New-AzureRmVirtualNetworkSubnetConfig -Name $gwSNNameWest -AddressPrefix "10.0.255.0/24"

$InfraSNNameWest = "West-VNET-Infrastructure-Subnet"
$InfraSNWest = New-AzureRmVirtualNetworkSubnetConfig -Name $InfraSNNameWest -AddressPrefix "10.0.0.0/24"

# Subnets belonging to East Location
$gwSNNameEast = "GatewaySubnet"
$gwSNEast = New-AzureRmVirtualNetworkSubnetConfig -Name $gwSNNameEast -AddressPrefix "192.168.255.0/24"

$AppSNNameEast = "East-VNET-App-Subnet"
$AppSNEast = New-AzureRmVirtualNetworkSubnetConfig -Name $AppSNNameEast -AddressPrefix "192.168.0.0/24"

# West Virtual Network Creation
Write-Verbose "Creating west virtual network" -Verbose
$vnetwest = New-AzureRmVirtualNetwork -Name "West-VNET" -ResourceGroupName $rgWest.ResourceGroupName -Location $westLocation -AddressPrefix "10.0.0.0/16" -Subnet $InfraSNWest,$gwSNWest

Write-Verbose "Creating east virtual network" -Verbose
$vneteast = New-AzureRmVirtualNetwork -Name "East-VNET" -ResourceGroupName $rgEast.ResourceGroupName -Location $eastLocation -AddressPrefix "192.168.0.0/16" -Subnet $AppSNEast,$gwSNEast 

# Establishing VNET to VNET Connection

# West side
Write-Verbose "Establishing VNET to VNET Connection, working on west side" -Verbose

# Public IP Address of the West Gateway
$gwpipWest = New-AzureRmPublicIpAddress -Name "$westLocation-gwpip" -ResourceGroupName $rgWest.ResourceGroupName -Location $westLocation -AllocationMethod Dynamic 

# West Gateway IP Configuration
$vnet = Get-AzureRmVirtualNetwork -Name "West-VNET" -ResourceGroupName $rgWest.ResourceGroupName
$subnet = Get-AzureRmVirtualNetworkSubnetConfig -Name 'GatewaySubnet' -VirtualNetwork $vnet 

$gwipconfigWest = New-AzureRmVirtualNetworkGatewayIpConfig -Name "$westlocation-gwipconfig" -SubnetId $subnet.Id -PublicIpAddressId $gwpipWest.Id 

# Creating West Gateway
Write-Verbose "Creating West Gateway" -Verbose

New-AzureRmVirtualNetworkGateway -Name "$westlocation-vnet-Gateway" `
                    -ResourceGroupName $rgWest.ResourceGroupName `
                    -Location $westlocation `
                    -IpConfigurations $gwipconfigWest `
                    -GatewayType Vpn `
                    -VpnType RouteBased `
                    -GatewaySku Basic `
                    -EnableBgp:$false

# East side
# Public IP Address of the East Gateway
$gwpipEast = New-AzureRmPublicIpAddress -Name "$eastLocation-gwpip" -ResourceGroupName $rgEast.ResourceGroupName -Location $eastLocation -AllocationMethod Dynamic 

#East Gateway IP Configuration
$vnet = Get-AzureRmVirtualNetwork -Name "East-VNET" -ResourceGroupName $rgEast.ResourceGroupName
$subnet = Get-AzureRmVirtualNetworkSubnetConfig -Name 'GatewaySubnet' -VirtualNetwork $vnet 

$gwipconfigEast = New-AzureRmVirtualNetworkGatewayIpConfig -Name "$eastlocation-gwipconfig" -SubnetId $subnet.Id -PublicIpAddressId $gwpipEast.Id 

#Creating East Gateway
Write-Verbose "Creating East Gateway" -Verbose
New-AzureRmVirtualNetworkGateway -Name "$eastlocation-vnet-Gateway" `
                    -ResourceGroupName $rgEast.ResourceGroupName `
                    -Location $eastlocation `
                    -IpConfigurations $gwipconfigEast `
                    -GatewayType Vpn `
                    -VpnType RouteBased `
                    -GatewaySku Basic `
                    -EnableBgp:$false

# Getting public ip of Gateway on West Location
$gw = Get-AzureRmVirtualNetworkGateway -ResourcegroupName $rgWest.ResourceGroupName
$WestGwPIP = (Get-AzureRmPublicIpAddress | ? { $_.id -eq $gw.IpConfigurations.publicipaddress.id }).IpAddress

# Getting public of Gateway on East Location
$gw = Get-AzureRmVirtualNetworkGateway -ResourcegroupName $rgEast.ResourceGroupName
$EastGwPIP = (Get-AzureRmPublicIpAddress | ? { $_.id -eq $gw.IpConfigurations.publicipaddress.id }).IpAddress

# Connecting Gateways
Write-Verbose "Connecting Gateways" -Verbose

# Creating Local Network Gateway on West Location
New-AzureRmLocalNetworkGateway -Name "$eastlocation-LocalNetworkGateway" -ResourceGroupName $rgWest.ResourceGroupName -Location $westlocation -GatewayIpAddress $EastGwPIP -AddressPrefix @("192.168.0.0/16")

# Creating Local Network Gateway on East Location
New-AzureRmLocalNetworkGateway -Name "$westlocation-LocalNetworkGateway" -ResourceGroupName $rgEast.ResourceGroupName -Location $eastlocation -GatewayIpAddress $WestGwPIP -AddressPrefix @("10.0.0.0/16")

# Creating West Gateway Connection
$gatewayWest = Get-AzureRmVirtualNetworkGateway -Name "$westlocation-vnet-Gateway" -ResourceGroupName $rgWest.ResourceGroupName
$localWest = Get-AzureRmLocalNetworkGateway -Name "$eastlocation-LocalNetworkGateway" -ResourceGroupName $rgWest.ResourceGroupName

$sharedKey = "<shared key here, only lower or upper case letters and numbers>"
New-AzureRmVirtualNetworkGatewayConnection -Name "$westlocation-gwConnection" `
                    -ResourceGroupName $rgWest.ResourceGroupName `
                    -Location $westlocation `
                    -VirtualNetworkGateway1 $gatewayWest `
                    -LocalNetworkGateway2 $localWest `
                    -ConnectionType IPsec `
                    -RoutingWeight 10 `
                    -SharedKey $sharedKey

# Creating East Gateway Connection
$gatewayEast = Get-AzureRmVirtualNetworkGateway -Name "$eastlocation-vnet-Gateway" -ResourceGroupName $rgEast.ResourceGroupName
$localEast = Get-AzureRmLocalNetworkGateway -Name "$westlocation-LocalNetworkGateway" -ResourceGroupName $rgEast.ResourceGroupName

New-AzureRmVirtualNetworkGatewayConnection -Name "$eastlocation-gwConnection" `
                    -ResourceGroupName $rgEast.ResourceGroupName `
                    -Location $eastlocation `
                    -VirtualNetworkGateway1 $gatewayEast `
                    -LocalNetworkGateway2 $localEast `
                    -ConnectionType IPsec `
                    -RoutingWeight 10 `
                    -SharedKey $sharedKey

# Creating load balancer that will be used by IIS servers

# Azure Load Balancer Public Ip Address
Write-Verbose "Creating the IIS Loadbalancer" -Verbose
$albPublicIpDNSName = "<public ip dns name>"
$albPublicIP = New-AzureRmPublicIpAddress   -Name "albIISpip" -ResourceGroupName $rgEast.ResourceGroupName -Location $eastlocation –AllocationMethod Static -DomainNameLabel $albPublicIpDNSName

##
## If you want to get the existing load balancer resource you can use the following cmdlet
## $albPublicIP = Get-AzureRmPublicIpAddress -ResourceGroupName $rgEast.ResourceGroupName -Name "albIISpip" `
##

# Defining Load Balancer items

# Front end IP Pool
$frontendIP = New-AzureRmLoadBalancerFrontendIpConfig -Name "albIISFrontEndIpConfig" -PublicIpAddress $albPublicIP

# Back End IP Pool
$beAddresspool = New-AzureRmLoadBalancerBackendAddressPoolConfig -Name "albIISBackEndIpConfig"

# NAT Rules - one Nat rule per server and public port, two in this case because we have two IIS servers attached to the LB
$inboundNATRule1= New-AzureRmLoadBalancerInboundNatRuleConfig -Name "IIS1Nat-RDP" -FrontendIpConfiguration $frontendIP -Protocol TCP -FrontendPort 3441 -BackendPort 3389
$inboundNATRule2= New-AzureRmLoadBalancerInboundNatRuleConfig -Name "IIS2Nat-RDP" -FrontendIpConfiguration $frontendIP -Protocol TCP -FrontendPort 3442 -BackendPort 3389

# HTTP probe
$wwwHealthProbe = New-AzureRmLoadBalancerProbeConfig -Name "WWWProbe" -RequestPath '/' -Protocol Http -Port 80 -IntervalInSeconds 10 -ProbeCount 2                  

# Load Balancer rule
$lbRule1 = New-AzureRmLoadBalancerRuleConfig -Name HTTP `
                    -FrontendIpConfiguration $frontendIP `
                    -BackendAddressPool  $beAddressPool `
                    -Probe $wwwHealthProbe `
                    -Protocol Tcp `
                    -FrontendPort 80 `
                    -BackendPort 80

# Load Balancer
$IISAlb = New-AzureRmLoadBalancer -ResourceGroupName $rgEast.ResourceGroupName `
                    -Name "POC-IIS-ALB" `
                    -Location $eastLocation  `
                    -FrontendIpConfiguration $frontendIP  `
                    -InboundNatRule $inboundNATRule1,$inboundNatRule2  `
                    -LoadBalancingRule $lbRule1 `
                    -BackendAddressPool $beAddressPool  `
                    -Probe $wwwHealthProbe 


# Public IP Address of Domain Controller - in this case we showcase that attached a server directly to a public ip address is possible
$dcpip = New-AzureRmPublicIpAddress -Name "dcpip" -ResourceGroupName $rgWest.ResourceGroupName -Location $westLocation -AllocationMethod Dynamic

# Creates NSG (Network Security Group) Rule for Domain Controller. Basically allow RDP from public network, allow all from east subnet.
Write-Verbose "Network Security Group" -Verbose

$rules = @()

$rules +=  New-AzureRmNetworkSecurityRuleConfig -Name "allow-rdp" `
			-Description "Allow inbound RDP from internet" `
			-Access Allow `
			-Protocol Tcp `
			-Direction Inbound `
			-Priority 100 `
			-SourceAddressPrefix Internet `
			-SourcePortRange * `
			-DestinationAddressPrefix * `
			-DestinationPortRange 3389

$rules +=  New-AzureRmNetworkSecurityRuleConfig -Name "allow-all-eastsubnet" `
			-Description "Allow inbound all ports from east subnet" `
			-Access Allow `
			-Protocol * `
			-Direction Inbound `
			-Priority 300 `
			-SourceAddressPrefix "192.0.0.0/16" `
			-SourcePortRange * `
			-DestinationAddressPrefix * `
			-DestinationPortRange *

# Create Network Security Group resource
$nsg =  New-AzureRmNetworkSecurityGroup -Name "DC-NSG" -ResourceGroupName $rgWest.ResourceGroupName -Location $westLocation -SecurityRules $rules

# Creates NSG (Network Security Group) Rule for IIS Subnet. Basically allow 3389 and 80 from public network, allow all from west subnet, 80 and 3389 from the load balancer.

$rules = @()

$rules +=  New-AzureRmNetworkSecurityRuleConfig -Name "allow-rdp" `
			-Description "Allow inbound RDP from loadbalancer" `
			-Access Allow `
			-Protocol Tcp `
			-Direction Inbound `
			-Priority 100 `
			-SourceAddressPrefix * `
			-SourcePortRange * `
			-DestinationAddressPrefix * `
			-DestinationPortRange 3389

$rules +=  New-AzureRmNetworkSecurityRuleConfig -Name "allow-80" `
			-Description "Allow inbound 80 from loadbalancer" `
			-Access Allow `
			-Protocol Tcp `
			-Direction Inbound `
			-Priority 200 `
			-SourceAddressPrefix * `
			-SourcePortRange * `
			-DestinationAddressPrefix * `
			-DestinationPortRange 80

$rules +=  New-AzureRmNetworkSecurityRuleConfig -Name "allow-all-westsubnet" `
			-Description "Allow inbound all ports from west subnet" `
			-Access Allow `
			-Protocol * `
			-Direction Inbound `
			-Priority 300 `
			-SourceAddressPrefix "10.0.0.0/16" `
			-SourcePortRange * `
			-DestinationAddressPrefix * `
			-DestinationPortRange *

$eastSnNsg =  New-AzureRmNetworkSecurityGroup -Name "East-SN-NSG" -ResourceGroupName $rgEast.ResourceGroupName -Location $eastLocation -SecurityRules $rules

# Associate NSG to Vnet
$vnet = Get-AzureRmVirtualNetwork -Name "East-VNET" -ResourceGroupName $rgEast.ResourceGroupName
$subnet = Get-AzureRmVirtualNetworkSubnetConfig -Name $AppSNNameEast -VirtualNetwork $vnet 

Set-AzureRmVirtualNetworkSubnetConfig -Name $AppSNNameEast -VirtualNetwork $vnet -NetworkSecurityGroup $eastSnNsg -AddressPrefix $subnet.AddressPrefix | `
	Set-AzureRmVirtualNetwork 

### End of Virtual Networks Section

### Start of Storage Accounts Section

##
## if you need to get an existing availability set resource you can use the following cmdlet
## $IISAVSet = Get-AzureRmAvailabilitySet -ResourceGroupName $rgEast.ResourceGroupName -Name $IISAVSetName
##

#-------------------------------------------------------
# Create Storage Account for East Region & West Region
#-------------------------------------------------------

Write-Verbose "Create Storage Account for East Region & West Region" -Verbose

# Storage Account Names must be unique - make sure to change it here
$saWestName = "<storage account name>"
New-AzureRmStorageAccount -ResourceGroupName $rgStorage.ResourceGroupName -Name $saWestName -Location $westLocation -Type Standard_LRS -Kind Storage 

# Storage Account Names must be unique - make sure to change it here
$saEastName = "<storage account name>"
New-AzureRmStorageAccount -ResourceGroupName $rgStorage.ResourceGroupName -Name $saEastName -Location $eastLocation -Type Standard_LRS -Kind Storage

# Creates Container for VHD's (Virtual Disks)
Write-Verbose "Creates Container for VHD's (Virtual Disks)" -Verbose
$saWest = Get-AzureRMStorageAccount -ResourceGroupName $rgStorage.ResourceGroupName -Name $saWestName
$saEast = Get-AzureRMStorageAccount -ResourceGroupName $rgStorage.ResourceGroupName -Name $saEastName
  
New-AzureStorageContainer -Name "vhds" -Permission Off -Context $saWest.Context -ErrorAction SilentlyContinue 
New-AzureStorageContainer -Name "vhds" -Permission Off -Context $saEast.Context -ErrorAction SilentlyContinue

### End of Storage Accounts Section

### Start of Deploying VMs Section

#---------------------------------------------- 
# Deploying VMs
#---------------------------------------------- 

# Windows 2012R2 VM Image
Write-Verbose "Selecting Windows 2012R2 VM Image" -Verbose
$vmRmImage = (Get-AzureRmVMImage -PublisherName "MicrosoftWindowsServer" -Location $westlocation -Offer "WindowsServer" -Skus "2012-R2-Datacenter" | Sort-Object -Descending -Property Version)[0]

# Domain Controller
Write-Verbose "Deploying a Domain Controller VM" -Verbose
$vmName = "dc"

# VM nic
Write-Verbose "   Setting up nic" -Verbose
$vnet  = Get-AzureRmVirtualNetwork -ResourceGroupName $rgWest.ResourceGroupName -Name "West-Vnet"
$subnet = Get-AzureRmVirtualNetworkSubnetConfig -Name $InfraSNNameWest -VirtualNetwork $vnet 

$dcnic = New-AzureRmNetworkInterface -ResourceGroupName $rgWest.ResourceGroupName `
                    -Location $westLocation `
                    -Name "$vmName-nic" `
                    -PrivateIpAddress "10.0.0.4" `
                    -PublicIpAddress $dcpip `
                    -Subnet $subnet `
                    -NetworkSecurityGroup $nsg 

##
## Optionally getting reference of an existing Nic
## $dcnic = Get-AzureRmNetworkInterface -ResourceGroupName $rgWest.ResourceGroupName -name "dc-nic"
##
 
# VM Config
Write-Verbose "   Working on vm configuration" -Verbose

$vmOSDiskName = [string]::Format("{0}-OSDisk",$vmName)
$vhdURI = [System.Uri]([string]::Format("https://{0}.blob.core.windows.net/vhds/{1}.vhd",$saWestName,$vmOSDiskName))

$vmDataDiskName = [string]::Format("{0}-DataDisk",$vmName)
$vhdDataDiskURI = [System.Uri]([string]::Format("https://{0}.blob.core.windows.net/vhds/{1}.vhd",$saWestName,$vmDataDiskName))

# User Name and password
$clearTextPassword =  "<complex password here>"
$password = ConvertTo-SecureString -String $clearTextPassword -AsPlainText -Force
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("localadmin", $password)
 
$dc01VmConfig = New-AzureRmVMConfig -VMName $vmName -VMSize "Standard_D1"

Set-AzureRmVMOperatingSystem -VM $dc01VmConfig -Windows -ComputerName $vmName -Credential $creds
Set-AzureRmVMSourceImage -VM $dc01VmConfig -PublisherName $vmRmImage.PublisherName -Offer $vmRmImage.Offer -Skus $vmRmImage.Skus -Version $vmRmImage.Version
Set-AzureRmVMOSDisk -VM $dc01VmConfig -Name $vmOSDiskName -VhdUri $vhdURI -Caching ReadWrite -CreateOption fromImage
Add-AzureRmVmDataDisk -VM $dc01VmConfig -Name $vmDataDiskName -DiskSizeInGB 1023 -VhdUri $vhdDataDiskURI -Caching None -Lun 0 -CreateOption Empty
Add-AzureRmVMNetworkInterface -VM $dc01VmConfig -Id $dcnic.Id
 
Write-Verbose "   Deploying vm" -Verbose

New-AzureRmVM -ResourceGroupName $rgWest.ResourceGroupName -Location $westlocation -VM $dc01VmConfig

# Promoting VM to be a Domain Controller via Powershell DSC
Write-Verbose "   Running Powershell DSC to promote vm as Domain Controller" -Verbose
Invoke-AzureRmPowershellDSCAD -OutputPackageFolder c:\deployment `
                            -DscScriptsFolder c:\deployment\DSC `
                            -DscConfigFile DCConfig.ps1 `
                            -DscConfigFunction DcConfig `
                            -dscConfigDataFile ConfigDataAD.psd1 `
                            -ResourceGroupName $rgWest.ResourceGroupName `
                            -VMName "DC" `
                            -StagingSaName $saWestName `
                            -stagingSaResourceGroupName $rgStorage.ResourceGroupName `
                            -Credentials $creds
# End of Domain Controller

# Since Domain Controller now is up and running, configure both virtual networks to use the DC as primary custom DNS instead of Azure DNS
$eastVnet = Get-AzureRmVirtualNetwork -Name "East-VNET" -ResourceGroupName $rgEast.ResourceGroupName
$eastVnet.DhcpOptions.DnsServers = @("10.0.0.4")
Set-AzureRmVirtualNetwork -VirtualNetwork $eastVnet

$westVnet = Get-AzureRmVirtualNetwork -Name "West-VNET" -ResourceGroupName $rgWest.ResourceGroupName
$westVnet.DhcpOptions.DnsServers = @("10.0.0.4")
Set-AzureRmVirtualNetwork -VirtualNetwork $westVnet

# IIS virtual machines

# Creating Availability set for IIS load balanced set
$IISAVSetName = "IIS-AS"
Write-Verbose "Creating Availability set for IIS load balanced set" -Verbose
$IISAVSet = New-AzureRmAvailabilitySet -ResourceGroupName $rgEast.ResourceGroupName -Name $IISAVSetName -Location $eastlocation  

# IIS01
$vmName = "iis01"
Write-Verbose "Deploying $vmName VM" -Verbose 

# VM nic
Write-Verbose "   Setting up nic" -Verbose
# Getting Vnet and subnet resources
$vnet  = Get-AzureRmVirtualNetwork -ResourceGroupName $rgEast.ResourceGroupName -Name "East-Vnet"
$AppSubnet = Get-AzureRmVirtualNetworkSubnetConfig -Name "East-VNET-App-Subnet" -VirtualNetwork $vnet

# Getting Load Balancer if needed 
$IISAlb = Get-AzureRmLoadBalancer -Name "POC-IIS-ALB"  -ResourceGroupName $rgEast.ResourceGroupName

# Nic creation, highlight the usage of DNS direct on NIC
$iis01nic = New-AzureRmNetworkInterface -ResourceGroupName $rgEast.ResourceGroupName `
                    -Location $eastLocation `
                    -Name "$vmName-nic" `
                    -PrivateIpAddress "192.168.0.4" `
                    -Subnet $AppSubnet `
                    -LoadBalancerBackendAddressPool $IISAlb.BackendAddressPools[0] `
                    -LoadBalancerInboundNatRule $IISAlb.InboundNatRules[0] `
                    -DnsServer 10.0.0.4

Write-Verbose "   Working on vm configuration" -Verbose

$vmOSDiskName = [string]::Format("{0}-OSDisk",$vmName)
$vhdURI = [System.Uri]([string]::Format("https://{0}.blob.core.windows.net/vhds/{1}.vhd",$saEastName,$vmOSDiskName))
 
$iisVmConfig01= New-AzureRmVMConfig -VMName $vmName -VMSize "Standard_D1" -AvailabilitySetId $IISAVSet.Id

Set-AzureRmVMOperatingSystem -VM $iisVmConfig01 -Windows -ComputerName $vmName -Credential $creds
Set-AzureRmVMSourceImage -VM $iisVmConfig01 -PublisherName $vmRmImage.PublisherName -Offer $vmRmImage.Offer -Skus $vmRmImage.Skus -Version $vmRmImage.Version
Set-AzureRmVMOSDisk -VM $iisVmConfig01 -Name $vmOSDiskName -VhdUri $vhdURI -Caching ReadWrite -CreateOption fromImage
Add-AzureRmVMNetworkInterface -VM $iisVmConfig01 -Id $iis01nic.Id

Write-Verbose "   Deploying vm" -Verbose
New-AzureRmVM -ResourceGroupName $rgEast.ResourceGroupName -Location $eastlocation -VM $iisVmConfig01

# Joining virtual machine to the domain 
Write-Verbose "   Joining VM to the domain" -Verbose
$domainName = "contosoad.com"
$JoinDomainUserName = "contosoad\localadmin"
$JoinDomainUserPassword = "<password here>"
Set-AzureRmVmExtension -ResourceGroupName $rgEast.ResourceGroupName `
                        -ExtensionType "JsonADDomainExtension" `
                        -Name "JoinDomain" `
                        -Publisher "Microsoft.Compute" `
                        -TypeHandlerVersion "1.3" `
                        -VMName $vmname `
                        -Location $eastLocation `
                        -Settings @{ "Name" = $DomainName; "OUPath" = ""; "User" = $JoinDomainUserName; "Restart" = "true"; "Options" = 3}  `
                        -ProtectedSettings @{"Password" = $JoinDomainUserPassword}  

# Configuring VM to hold IIS feature via Powershell DSC
Write-Verbose "   Running PowerShell DSC to configure VM as IIS server" -Verbose
Invoke-AzureRmPowershellDSCIIS -OutputPackageFolder c:\deployment `
                            -DscScriptsFolder c:\deployment\DSC `
                            -DscConfigFile IISInstall.ps1 `
                            -DscConfigFunction IISInstall `
                            -ResourceGroupName $rgEast.ResourceGroupName `
                            -VMName $vmname  `
                            -StagingSaName $saEastName `
                            -stagingSaResourceGroupName $rgStorage.ResourceGroupName

# IIS 02 VM
$vmName = "iis02"
Write-Verbose "Deploying $vmName VM" -Verbose 
Write-Verbose "   Setting up nic" -Verbose
$iis02nic = New-AzureRmNetworkInterface -ResourceGroupName $rgEast.ResourceGroupName `
                    -Location $eastLocation `
                    -Name "$vmName-nic" `
                    -PrivateIpAddress "192.168.0.5" `
                    -Subnet $AppSubnet `
                    -LoadBalancerBackendAddressPool $IISAlb.BackendAddressPools[0] `
                    -LoadBalancerInboundNatRule $IISAlb.InboundNatRules[1] `
                    -DnsServer 10.0.0.4

Write-Verbose "   Working on vm configuration" -Verbose
$vmOSDiskName = [string]::Format("{0}-OSDisk",$vmName)
$vhdURI = [System.Uri]([string]::Format("https://{0}.blob.core.windows.net/vhds/{1}.vhd",$saEastName,$vmOSDiskName))
 
$iisVmConfig02= New-AzureRmVMConfig -VMName $vmName -VMSize "Standard_D1" -AvailabilitySetId $IISAVSet.Id

Set-AzureRmVMOperatingSystem -VM $iisVmConfig02 -Windows -ComputerName $vmName -Credential $creds
Set-AzureRmVMSourceImage -VM $iisVmConfig02 -PublisherName $vmRmImage.PublisherName -Offer $vmRmImage.Offer -Skus $vmRmImage.Skus -Version $vmRmImage.Version
Set-AzureRmVMOSDisk -VM $iisVmConfig02 -Name $vmOSDiskName -VhdUri $vhdURI -Caching ReadWrite -CreateOption fromImage
Add-AzureRmVMNetworkInterface -VM $iisVmConfig02 -Id $iis02nic.Id

Write-Verbose "   Deploying vm" -Verbose
New-AzureRmVM -ResourceGroupName $rgEast.ResourceGroupName -Location $eastlocation -VM $iisVmConfig02

# Joining virtual machine to the domain 
Write-Verbose "   Joining VM to the domain" -Verbose
Set-AzureRmVmExtension -ResourceGroupName $rgEast.ResourceGroupName `
                        -ExtensionType "JsonADDomainExtension" `
                        -Name "JoinDomain" `
                        -Publisher "Microsoft.Compute" `
                        -TypeHandlerVersion "1.3" `
                        -VMName $vmname `
                        -Location $eastLocation `
                        -Settings @{ "Name" = $DomainName; "OUPath" = ""; "User" = $JoinDomainUserName; "Restart" = "true"; "Options" = 3}  `
                        -ProtectedSettings @{"Password" = $JoinDomainUserPassword}  

# Configuring VM to hold IIS feature via Powershell DSC
Write-Verbose "   Running PowerShell DSC to configure VM as IIS server" -Verbose
Invoke-AzureRmPowershellDSCIIS -OutputPackageFolder c:\deployment `
                            -DscScriptsFolder c:\deployment\DSC `
                            -DscConfigFile IISInstall.ps1 `
                            -DscConfigFunction IISInstall `
                            -ResourceGroupName $rgEast.ResourceGroupName `
                            -VMName $vmname  `
                            -StagingSaName $saEastName `
                            -stagingSaResourceGroupName $rgStorage.ResourceGroupName

# End of IIS virtual machines

### End of Deploying VMs Section