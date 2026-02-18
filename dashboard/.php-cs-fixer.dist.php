<?php

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__)
    ->exclude('lib')
    ->exclude('widgets/vnstat.php')
    ->name('*.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);

$config = new PhpCsFixer\Config();
return $config->setRules([
    '@PSR12' => true,
    'array_syntax' => ['syntax' => 'short'],
])
    ->setFinder($finder);
