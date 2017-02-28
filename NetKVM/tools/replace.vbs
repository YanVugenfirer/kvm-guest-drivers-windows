If WScript.Arguments.Count <> 3 then
  WScript.Echo "usage: Find_And_replace.vbs filename word_to_find replace_with "
  WScript.Quit
end If

FindAndReplace WScript.Arguments.Item(0), WScript.Arguments.Item(1), WScript.Arguments.Item(2)
WScript.Echo "Operation Complete"

function FindAndReplace(strFilename, strFind, strReplace)
    Set inputFile = CreateObject("Scripting.FileSystemObject").OpenTextFile(strFilename, 1)
    strInputFile = inputFile.ReadAll
    inputFile.Close
    Set inputFile = Nothing
    Set outputFile = CreateObject("Scripting.FileSystemObject").OpenTextFile(strFilename,2,true)
    outputFile.Write Replace(strInputFile, strFind, strReplace)
    outputFile.Close
    Set outputFile = Nothing
end function 