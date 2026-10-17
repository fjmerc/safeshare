// Validates Word, Excel and PowerPoint files with Microsoft's Open XML SDK,
// the closest check to "Office opens it" available without Office. Used on
// the stripped outputs of tests/js/office-metadata.test.js; exits non-zero if
// any file can't be opened or has schema errors.
//
//   dotnet run --project tests/js/validate-ooxml -- out/*.docx out/*.xlsx out/*.pptx
using System;
using System.IO;
using System.Linq;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Validation;

var failed = 0;
foreach (var file in args)
{
    try
    {
        var ext = Path.GetExtension(file).ToLowerInvariant();
        using OpenXmlPackage doc = ext switch
        {
            ".docx" or ".docm" => WordprocessingDocument.Open(file, false),
            ".xlsx" or ".xlsm" => SpreadsheetDocument.Open(file, false),
            ".pptx" or ".pptm" => PresentationDocument.Open(file, false),
            _ => throw new ArgumentException("not an Office file"),
        };
        var errors = new OpenXmlValidator(FileFormatVersions.Microsoft365).Validate(doc).ToList();
        Console.WriteLine($"{(errors.Count == 0 ? "PASS" : "FAIL")} {Path.GetFileName(file)}: {errors.Count} errors");
        foreach (var e in errors.Take(10)) Console.WriteLine($"     {e.Part?.Uri} {e.Path?.XPath}: {e.Description}");
        if (errors.Count > 0) failed++;
    }
    catch (Exception e)
    {
        Console.WriteLine($"FAIL {Path.GetFileName(file)}: can't open: {e.Message}");
        failed++;
    }
}
if (args.Length == 0) { Console.WriteLine("FAIL no files given"); failed++; }
return failed == 0 ? 0 : 1;
