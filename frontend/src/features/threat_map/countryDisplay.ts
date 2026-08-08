const COUNTRY_CODE_PATTERN = /^[A-Z]{2}$/;

export function countryFlagCode(country: string | null | undefined): string | null {
  const code = (country ?? "").trim().toUpperCase();
  return COUNTRY_CODE_PATTERN.test(code) ? code : null;
}

export function countryLabelText(
  country: string | null | undefined,
  text: string | null | undefined = country,
): string {
  const label = (text ?? "").trim();
  if (label) return label;

  return (country ?? "").trim().toUpperCase();
}
