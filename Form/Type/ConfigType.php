<?php

declare(strict_types=1);

namespace MauticPlugin\LaravelOidcBundle\Form\Type;

use Mautic\CoreBundle\Form\DataTransformer\ArrayLinebreakTransformer;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;

class ConfigType extends AbstractType
{
    /**
     * @param  array<mixed>  $options
     */
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $this->addText($builder, 'oidc_scopes', 'plugin.laraveloidc.config.scopes', 'plugin.laraveloidc.config.scopes.tooltip');
        $this->addText($builder, 'oidc_username_claim', 'mautic.core.username');
        $this->addText($builder, 'oidc_email_claim', 'mautic.core.type.email');
        $this->addText($builder, 'oidc_first_name_claim', 'mautic.core.firstname', required: false);
        $this->addText($builder, 'oidc_last_name_claim', 'mautic.core.lastname', required: false);
        $this->addText($builder, 'oidc_timezone_claim', 'mautic.core.timezone', required: false);
        $this->addText($builder, 'oidc_locale_claim', 'mautic.core.language', required: false);
        $this->addLines($builder, 'oidc_required_claims', 'plugin.laraveloidc.config.required_claims', 'plugin.laraveloidc.config.required_claims.tooltip');
        $this->addText($builder, 'oidc_role_claim', 'plugin.laraveloidc.config.role_claim', 'plugin.laraveloidc.config.role_claim.tooltip', required: false);
        $this->addLines($builder, 'oidc_role_mapping', 'plugin.laraveloidc.config.role_mapping', 'plugin.laraveloidc.config.role_mapping.tooltip');
        $this->addText($builder, 'oidc_api_user_email', 'plugin.laraveloidc.config.api_user_email', 'plugin.laraveloidc.config.api_user_email.tooltip', required: false);
        $this->addLines($builder, 'oidc_api_allowed_client_ids', 'plugin.laraveloidc.config.api_allowed_client_ids', 'plugin.laraveloidc.config.api_allowed_client_ids.tooltip');
        $this->addText($builder, 'oidc_api_audience', 'plugin.laraveloidc.config.api_audience', 'plugin.laraveloidc.config.api_audience.tooltip', required: false);
    }

    public function getBlockPrefix(): string
    {
        return 'laraveloidcconfig';
    }

    private function addText(FormBuilderInterface $builder, string $name, string $label, ?string $tooltip = null, bool $required = true): void
    {
        $builder->add($name, TextType::class, [
            'label' => $label,
            'label_attr' => ['class' => 'control-label'],
            'attr' => array_filter(['class' => 'form-control', 'tooltip' => $tooltip]),
            'required' => $required,
        ]);
    }

    private function addLines(FormBuilderInterface $builder, string $name, string $label, string $tooltip): void
    {
        $builder->add(
            $builder->create($name, TextareaType::class, [
                'label' => $label,
                'label_attr' => ['class' => 'control-label'],
                'attr' => ['class' => 'form-control', 'tooltip' => $tooltip, 'rows' => 4],
                'required' => false,
            ])->addViewTransformer(new ArrayLinebreakTransformer)
        );
    }
}
