package privacy

import "time"

// neverExpireYear is the year at and after which an expiry is treated as the
// "never expires" sentinel (the user dashboard stores 9999-12-31) and left
// untouched, so rounding up cannot overflow into year 10000.
const neverExpireYear = 9999

// RoundDownToHour truncates t to the start of its UTC hour. Anonymous mode
// uses it for "when did this happen" fields (file created_at, scanned_at) so a
// seized database cannot be lined up against network logs by exact time.
func RoundDownToHour(t time.Time) time.Time {
	return t.UTC().Truncate(time.Hour)
}

// RoundUpToHour rounds t up to the next UTC hour boundary (t itself if it is
// already on one). The result is always >= t. Anonymous mode uses it for
// expiry times so rounding can only extend a file's life by less than an hour,
// never shorten it. Never-expire sentinels (year >= 9999) are returned as is.
func RoundUpToHour(t time.Time) time.Time {
	if t.Year() >= neverExpireYear {
		return t
	}
	t = t.UTC()
	r := t.Truncate(time.Hour)
	if r.Before(t) {
		r = r.Add(time.Hour)
	}
	return r
}
