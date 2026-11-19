import { Transform } from 'class-transformer';
import { ValidateBy, type ValidationOptions } from 'class-validator';

/** SPEC 4, exactly: ASCII only, nothing a mail library could re-read as `Name <other@address>`. */
export const EMAIL_REGEX = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/;

/** Length in Unicode characters (code points), not UTF-16 units, so "15–128 characters" means what it says. */
export const CharLength = (min: number, max: number, options?: ValidationOptions) =>
  ValidateBy(
    {
      name: 'charLength',
      constraints: [min, max],
      validator: {
        validate: (value: unknown) => typeof value === 'string' && [...value].length >= min && [...value].length <= max,
        defaultMessage: (args) => `${args?.property} must be between ${min} and ${max} characters`,
      },
    },
    options,
  );

/** Normalised email (see NormalizeEmail) matching EMAIL_REGEX, at most 254 characters. */
export const IsStrictEmail = (options?: ValidationOptions) =>
  ValidateBy(
    {
      name: 'isStrictEmail',
      validator: {
        validate: (value: unknown) => typeof value === 'string' && value.length <= 254 && EMAIL_REGEX.test(value),
        defaultMessage: (args) => `${args?.property} must be a valid email address`,
      },
    },
    options,
  );

/** SPEC 1: `name` and `filename` reject U+0000–U+001F and U+007F (Postgres cannot store NUL). */
export const NoControlChars = (options?: ValidationOptions) =>
  ValidateBy(
    {
      name: 'noControlChars',
      validator: {
        // eslint-disable-next-line no-control-regex
        validate: (value: unknown) => typeof value === 'string' && !/[\u0000-\u001f\u007f]/.test(value),
        defaultMessage: (args) => `${args?.property} must not contain control characters`,
      },
    },
    options,
  );

/**
 * Query-string integer: only plain decimal digits are accepted ("1.5", "1e3", "abc" become NaN and fail @IsInt);
 * huge values stay huge so @Max rejects them instead of wrapping.
 */
export const ToQueryInt = () =>
  Transform(({ value }: { value: unknown }) => {
    if (value === undefined) return value;
    return typeof value === 'string' && /^[0-9]{1,20}$/.test(value) ? Number(value) : Number.NaN;
  });

/** SPEC: strings are trimmed for `email` and `name` only. */
export const Trim = () => Transform(({ value }: { value: unknown }) => (typeof value === 'string' ? value.trim() : value));

/** SPEC: email is trimmed + lowercased before validating, storing or looking up. */
export const NormalizeEmail = () =>
  Transform(({ value }: { value: unknown }) => (typeof value === 'string' ? value.trim().toLowerCase() : value));
