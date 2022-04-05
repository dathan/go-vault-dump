package transform

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	err     error
	secrets map[string]interface{}
	params  map[string]interface{}
)

func Transform(transforms map[string]interface{}, input map[string]interface{}) (map[string]interface{}, error) {
	secrets = input
	for _, ttx := range transforms["transforms"].([]interface{}) {
		params = make(map[string]interface{})
		for ii, tt := range ttx.([]interface{}) {
			for kk, vv := range secrets {
				tx := tt.(map[string]interface{})
				xk, xv, err := apply(tx, kk, vv, ii)
				if err != nil {
					return nil, err
				}
				secrets[xk] = xv
				if xk != kk {
					delete(secrets, kk)
					if pk, hasParams := params[kk]; hasParams {
						params[xk] = pk
						delete(params, kk)
					}
				}
			}
		}
	}
	return secrets, nil
}

func apply(tx map[string]interface{}, key string, val interface{}, ii int) (string, interface{}, error) {
	scope := tx["scope"].(string)
	kk := key
	vv := val

	if rr, hasRequirement := tx["require"]; hasRequirement {
		if pp, hasParams := params[kk]; hasParams {
			if _, found := pp.(map[string]string)[fmt.Sprintf("{{%s}}", rr.(string))]; !found {
				return key, val, nil
			}
		} else {
			return key, val, nil
		}
	}

	if ff, hasFrom := tx["from"]; hasFrom {
		fk := render(ff.(string), key)
		if lookup, lookupSuccess := secrets[fk]; lookupSuccess {
			kk = fk
			vv = lookup
		}
	}

	work := ""
	if scope == "key" {
		work = kk
	} else if scope == "value" {
		jj, err := json.Marshal(vv)
		if err != nil {
			return "", nil, err
		}
		work = string(jj)
	} else {
		return "", nil, errors.New("'scope' must be either 'key' or 'value'")
	}

	if extract, doExtract := tx["extract"]; doExtract {
		re := regexp.MustCompile(extract.(string))
		matches := re.FindStringSubmatchIndex(work)
		if len(matches) > 0 {
			pk := key
			if to, hasTo := tx["to"]; hasTo {
				pk = render(to.(string), key)
			}
			pp, hasKey := params[pk]
			if !hasKey {
				pp = make(map[string]string)
				params[pk] = pp
			}
			for _, mm := range re.SubexpNames() {
				if mm != "" {
					result := []byte{}
					result = re.ExpandString(result, fmt.Sprintf("${%s}", mm), work, matches)
					pp.(map[string]string)[fmt.Sprintf("{{%s}}", mm)] = string(result)
				}
			}
		}
	} else if replace, doReplace := tx["replace"]; doReplace {
		if ww, hasWith := tx["with"]; hasWith {
			with := render(ww.(string), key)
			work = strings.ReplaceAll(work, replace.(string), with)
		} else {
			return "", nil, errors.New("'replace' actions must include 'with'")
		}
		if scope == "key" {
			key = work
		} else if scope == "value" {
			err = json.Unmarshal([]byte(work), &val)
			if err != nil {
				return "", nil, err
			}
		}
	}
	return key, val, nil
}

func render(ss string, kk string) string {
	if pp, hasParams := params[kk]; hasParams {
		for pk, pv := range pp.(map[string]string) {
			if len(pv) > 0 {
				ss = strings.ReplaceAll(ss, pk, pv)
			}
		}
	}
	return ss
}
