package main

import (
	"errors"

	"github.com/IBM-Cloud/bluemix-go/api/cis/cisv1"
)

var (
	// ErrNotFound indicates the error is because the requested object was not found.
	ErrNotFound = errors.New("not found")
)

func findZone(client cisv1.CisServiceAPI, crn, zoneQuery string) (*cisv1.Zone, error) {
	zones, err := client.Zones().ListZones(crn)
	if err != nil {
		return nil, err
	}

	for _, zone := range zones {
		if zone.Id == zoneQuery || zone.Name == zoneQuery {
			return &zone, nil
		}
	}

	return nil, ErrNotFound
}

func findRecord(client cisv1.CisServiceAPI, crn, zoneID, recordQuery, recordType, contentQuery string) (*cisv1.DnsRecord, error) {
	records, err := client.Dns().ListDns(crn, zoneID)
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		if (record.Id == recordQuery || record.Name == recordQuery) &&
			(contentQuery == "" || record.Content == contentQuery) &&
			record.DnsType == recordType {
			return &record, nil
		}
	}

	return nil, ErrNotFound
}
