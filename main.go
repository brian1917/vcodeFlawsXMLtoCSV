package main

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// Flaw represents a finding from a Veracode scan
type Flaw struct {
	Issueid                 string `xml:"issueid,attr"`
	CweName                 string `xml:"categoryname,attr"`
	Cweid                   string `xml:"cweid,attr"`
	RemediationStatus       string `xml:"remediation_status,attr"`
	MitigationStatus        string `xml:"mitigation_status,attr"`
	AffectsPolicyCompliance string `xml:"affects_policy_compliance,attr"`
	DateFirstOccurrence     string `xml:"date_first_occurrence,attr"`
	Severity                string `xml:"severity,attr"`
	ExploitLevel            string `xml:"exploitLevel,attr"`
	Module                  string `xml:"module,attr"`
	Sourcefile              string `xml:"sourcefile,attr"`
	Line                    string `xml:"line,attr"`
	SourceFilePath          string `xml:"sourcefilepath,attr"`
	Description             string `xml:"description,attr"`
	FlawURL                 string `xml:"url,attr"`
	VulnParameter           string `xml:"vuln_parameter,attr"`
}

func main() {

	var xmlFile []uint8
	var err error
	var resultsFile *os.File

	flawCount := 0

	inputXML := flag.String("xml", "", "Input XML file that should be converted to CSV.")
	flag.Parse()

	// Read the XML file
	if xmlFile, err = ioutil.ReadFile(*inputXML); err != nil {
		log.Fatal(err)
	}

	// Remove the ISO-8859-1 header
	xmlFile = bytes.Replace(xmlFile, []byte("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"),
		[]byte("<?xml version=\"1.0\"?>"), 1)

	// Create a CSV file for the results
	if resultsFile, err = os.Create(*inputXML + ".csv"); err != nil {
		log.Fatal(err)
	}
	defer resultsFile.Close()

	// Create the writer
	writer := csv.NewWriter(resultsFile)
	defer writer.Flush()

	// Write the headers
	headers := []string{"issueid", "categoryname", "cweid", "remediation_status", "mitigation_status", "affects_policy_compliance", "date_first_occurrence",
		"severity", "exploitLevel", "module", "sourcefile", "line", "sourcefilepath", "description", "url", "vuln_parameter"}
	if err = writer.Write(headers); err != nil {
		log.Fatal(err)
	}

	// Create a new decoder from the XML file
	decoder := xml.NewDecoder(bytes.NewReader(xmlFile))

	for {
		// Read tokens from the XML document in a stream.
		t, _ := decoder.Token()

		if t == nil {
			break
		}
		// Inspect the type of the token just read
		switch se := t.(type) {
		case xml.StartElement:
			// Read StartElement and check for flaw
			if se.Name.Local == "flaw" {
				var f Flaw
				decoder.DecodeElement(&f, &se)
				// Clean the data
				if len(f.SourceFilePath) == 0 {
					f.SourceFilePath = "NA"
				}
				if len(f.Sourcefile) == 0 {
					f.Sourcefile = "NA"
				}
				if len(f.VulnParameter) == 0 {
					f.VulnParameter = "NA"
				}
				if len(f.FlawURL) == 0 {
					f.FlawURL = "NA"
				}
				// Create entry array and write and write to CSV
				entry := []string{f.Issueid, f.CweName, f.Cweid, f.RemediationStatus, f.MitigationStatus, f.AffectsPolicyCompliance, f.DateFirstOccurrence,
					f.Severity, f.ExploitLevel, f.Module, f.Sourcefile, f.Line, f.SourceFilePath, f.Description, f.FlawURL, f.VulnParameter}
				err := writer.Write(entry)
				if err != nil {
					log.Fatal(err)
				}
				flawCount++
			}
		}
	}
	fmt.Printf("Created %v with %v flaws \n", *inputXML+".csv", flawCount)
}
