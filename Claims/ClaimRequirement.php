<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Claims;

final readonly class ClaimRequirement
{
    public function __construct(
        public string $path,
        public string $expected,
    ) {}

    public static function fromLine(string $line): ?self
    {
        $line = trim($line);

        if ($line === '' || str_starts_with($line, '#')) {
            return null;
        }

        $separator = strpos($line, '=');

        if ($separator === false) {
            return new self($line, 'true');
        }

        $path = trim(substr($line, 0, $separator));

        if ($path === '') {
            return null;
        }

        return new self($path, trim(substr($line, $separator + 1)));
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function isSatisfiedBy(array $claims): bool
    {
        $value = ClaimPath::read($claims, $this->path);

        if (is_array($value)) {
            if (! array_is_list($value)) {
                return false;
            }

            foreach ($value as $element) {
                if ($this->matches($element)) {
                    return true;
                }
            }

            return false;
        }

        return $this->matches($value);
    }

    public function describe(): string
    {
        return $this->path.'='.$this->expected;
    }

    private function matches(mixed $value): bool
    {
        if (is_bool($value)) {
            return ($value ? 'true' : 'false') === strtolower($this->expected);
        }

        if (! is_scalar($value)) {
            return false;
        }

        return (string) $value === $this->expected;
    }
}
