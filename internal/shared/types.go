package shared

import (
	"database/sql/driver"
	"fmt"
	"io"
	"strconv"
	"time"
)

type NullUnixTime struct {
	Time  time.Time
	Valid bool
}

func NewNullUnixTime(tm *time.Time) NullUnixTime {
	var tmp time.Time
	if tm != nil {
		tmp = *tm
	}
	return NullUnixTime{
		Time:  tmp,
		Valid: tm != nil,
	}
}

func (nt *NullUnixTime) Scan(value any) error {
	if value == nil {
		nt.Time = time.Time{}
		nt.Valid = false
		return nil
	}

	switch v := value.(type) {
	case int64:
		nt.Time = time.Unix(v, 0).UTC()
	case []byte:
		i, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			return err
		}
		nt.Time = time.Unix(i, 0).UTC()
	case string:
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			nt.Time = time.Unix(i, 0).UTC()
		} else {
			t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", v)
			if err != nil {
				return err
			}
			nt.Time = t
		}
	default:
		return fmt.Errorf("unsupported type %T for NullUnixTime", value)
	}

	nt.Valid = true
	return nil
}

func (nt NullUnixTime) Value() (driver.Value, error) {
	if !nt.Valid {
		return nil, nil
	}

	return nt.Time.Unix(), nil
}

func (nt NullUnixTime) Ptr() *time.Time {
	if !nt.Valid {
		return nil
	}
	t := nt.Time
	return &t
}

type UnixTime time.Time

func (ut *UnixTime) Scan(value any) error {
	if value == nil {
		return fmt.Errorf("cannot scan NULL into UnixTime")
	}

	switch v := value.(type) {
	case int64:
		*ut = UnixTime(time.Unix(v, 0).UTC())
	case []byte:
		i, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			return err
		}
		*ut = UnixTime(time.Unix(i, 0).UTC())
	case time.Time:
		*ut = UnixTime(v)
	case string:
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			*ut = UnixTime(time.Unix(i, 0).UTC())
		} else {
			t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", v)
			if err != nil {
				return err
			}
			*ut = UnixTime(t)
		}
	default:
		return fmt.Errorf("unsupported type %T for UnixTime", value)
	}

	return nil
}

func (ut UnixTime) Value() (driver.Value, error) {
	return time.Time(ut).Unix(), nil
}

func (ut UnixTime) Time() time.Time {
	return time.Time(ut)
}

type SinatureByte [32]byte

func (h SinatureByte) Value() (driver.Value, error) {
	return h[:], nil
}

func (h *SinatureByte) Scan(src any) error {
	if src == nil {
		return nil
	}
	b, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("Unkow error")
	}
	if len(b) != 32 {
		return fmt.Errorf("Hash.Scan: invalid lenght: %d", len(b))
	}

	copy(h[:], b)
	return nil
}

type File struct {
	Filename string
	Reader   io.ReadSeekCloser
	Size     int64
	MimeType string
}
