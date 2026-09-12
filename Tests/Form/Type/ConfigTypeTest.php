<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Tests\Form\Type;

use MauticPlugin\LaravelOidcBundle\Form\Type\ConfigType;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Form\Forms;

final class ConfigTypeTest extends TestCase
{
    /**
     * Mautic renders the tab straight through this block, with no form_rest()
     * anywhere in the chain, so a field the theme omits is invisible in the UI
     * and submitted empty on every save of the tab.
     */
    public function test_the_theme_renders_every_field_the_form_builds(): void
    {
        $builder = Forms::createFormFactory()->createBuilder();
        (new ConfigType)->buildForm($builder, []);
        $theme = (string) file_get_contents(
            __DIR__.'/../../../Resources/views/FormTheme/Config/_config_laraveloidcconfig_widget.html.twig',
        );

        foreach (array_keys($builder->all()) as $field) {
            self::assertStringContainsString(
                "form.{$field})",
                $theme,
                "The config theme does not render [{$field}], so saving the tab would clear it.",
            );
        }
    }
}
