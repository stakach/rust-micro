#![no_std]

pub const WALL_CLOCK_VALID: u32 = 1 << 0;
pub const WALL_CLOCK_UTC: u32 = 1 << 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WallClockSnapshot {
    pub unix_seconds: i64,
    pub timezone_minutes: i32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    InvalidBcd,
    InvalidDate,
    InvalidTimezone,
}

/// Decode BOOTBOOT's UTC `yyyymmddhhiiss` BCD timestamp into a portable Unix epoch.
///
/// Byte seven is the bootloader's daylight indicator and does not alter the UTC timestamp.
pub fn decode_bcd_utc(
    datetime: [u8; 8],
    timezone_minutes: i16,
) -> Result<WallClockSnapshot, DecodeError> {
    if !(-1440..=1440).contains(&timezone_minutes) {
        return Err(DecodeError::InvalidTimezone);
    }
    let century = decode_bcd(datetime[0])? as i32;
    let year_in_century = decode_bcd(datetime[1])? as i32;
    let year = century * 100 + year_in_century;
    let month = decode_bcd(datetime[2])? as u32;
    let day = decode_bcd(datetime[3])? as u32;
    let hour = decode_bcd(datetime[4])? as u32;
    let minute = decode_bcd(datetime[5])? as u32;
    let second = decode_bcd(datetime[6])? as u32;

    if year == 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(DecodeError::InvalidDate);
    }

    let days = days_before_year(year) + days_before_month(year, month) + i64::from(day - 1)
        - days_before_year(1970);
    let unix_seconds = days
        .checked_mul(86_400)
        .and_then(|seconds| seconds.checked_add(i64::from(hour) * 3_600))
        .and_then(|seconds| seconds.checked_add(i64::from(minute) * 60))
        .and_then(|seconds| seconds.checked_add(i64::from(second)))
        .ok_or(DecodeError::InvalidDate)?;
    Ok(WallClockSnapshot {
        unix_seconds,
        timezone_minutes: i32::from(timezone_minutes),
        flags: WALL_CLOCK_VALID | WALL_CLOCK_UTC,
    })
}

fn decode_bcd(value: u8) -> Result<u8, DecodeError> {
    let high = value >> 4;
    let low = value & 0x0f;
    if high > 9 || low > 9 {
        Err(DecodeError::InvalidBcd)
    } else {
        Ok(high * 10 + low)
    }
}

const fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

const fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn days_before_year(year: i32) -> i64 {
    let preceding = year as i64 - 1;
    preceding * 365 + preceding / 4 - preceding / 100 + preceding / 400
}

const fn days_before_month(year: i32, month: u32) -> i64 {
    const OFFSETS: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    OFFSETS[(month - 1) as usize]
        + if month > 2 && is_leap_year(year) {
            1
        } else {
            0
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bcd(value: u8) -> u8 {
        (value / 10) << 4 | value % 10
    }

    fn datetime(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> [u8; 8] {
        [
            bcd((year / 100) as u8),
            bcd((year % 100) as u8),
            bcd(month),
            bcd(day),
            bcd(hour),
            bcd(minute),
            bcd(second),
            0,
        ]
    }

    #[test]
    fn decodes_unix_epoch_and_preserves_timezone_metadata() {
        assert_eq!(
            decode_bcd_utc(datetime(1970, 1, 1, 0, 0, 0), 600),
            Ok(WallClockSnapshot {
                unix_seconds: 0,
                timezone_minutes: 600,
                flags: WALL_CLOCK_VALID | WALL_CLOCK_UTC,
            })
        );
    }

    #[test]
    fn handles_gregorian_leap_boundaries() {
        let leap = decode_bcd_utc(datetime(2000, 3, 1, 0, 0, 0), 0).unwrap();
        let prior = decode_bcd_utc(datetime(2000, 2, 28, 0, 0, 0), 0).unwrap();
        assert_eq!(leap.unix_seconds - prior.unix_seconds, 2 * 86_400);
        assert_eq!(
            decode_bcd_utc(datetime(2100, 2, 29, 0, 0, 0), 0),
            Err(DecodeError::InvalidDate)
        );
    }

    #[test]
    fn rejects_zero_dates_invalid_bcd_and_invalid_timezone() {
        assert_eq!(decode_bcd_utc([0; 8], 0), Err(DecodeError::InvalidDate));
        let mut invalid_bcd = datetime(2026, 8, 30, 1, 2, 3);
        invalid_bcd[5] = 0xfa;
        assert_eq!(decode_bcd_utc(invalid_bcd, 0), Err(DecodeError::InvalidBcd));
        assert_eq!(
            decode_bcd_utc(datetime(2026, 8, 30, 1, 2, 3), 1441),
            Err(DecodeError::InvalidTimezone)
        );
    }
}
