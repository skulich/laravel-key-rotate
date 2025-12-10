<?php

use Dotenv\Dotenv;
use Illuminate\Console\Command;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Database\Eloquent\Casts\AsEncryptedArrayObject;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SergKulich\LaravelKeyRotate\Console\KeyRotateCommand;
use SergKulich\LaravelKeyRotate\Events\KeyRotatedEvent;
use SergKulich\LaravelKeyRotate\Facades\KeyRotate;
use Workbench\App\Casts\CustomCast;
use Workbench\App\Models\Secret;
use Workbench\App\Models\User;

use function Orchestra\Testbench\workbench_path;

it('fails without APP_KEY', function () {
    config(['app.key' => null]);

    $this->artisan(KeyRotateCommand::class, ['--force' => true])
        ->assertExitCode(Command::FAILURE);
});

it('fails if APP_KEY is modified', function () {
    config(['app.key' => 'modified-key']);

    $this->artisan(KeyRotateCommand::class, ['--force' => true])
        ->assertExitCode(Command::FAILURE);
});

it('succeeds with сonfirmation', function () {
    $this->artisan(KeyRotateCommand::class)
        ->expectsConfirmation('Are you sure you want to run this command?', 'yes')
        ->assertExitCode(Command::SUCCESS);
});

it('fails without сonfirmation', function () {
    $this->artisan(KeyRotateCommand::class)
        ->expectsConfirmation('Are you sure you want to run this command?', 'no')
        ->assertExitCode(Command::FAILURE);
});

it('dispatches event', function () {
    Event::fake([KeyRotatedEvent::class]);

    $this->artisan(KeyRotateCommand::class, ['--force' => true])
        ->assertExitCode(Command::SUCCESS);

    Event::assertDispatched(KeyRotatedEvent::class, 1);
});

it('rotates app key', function () {
    // Zero Arrange
    $zeroEnv = Dotenv::parse(file_get_contents($this->app->environmentFilePath()));
    $zeroAppKey = $zeroEnv['APP_KEY'];

    // First Act
    $this->artisan(KeyRotateCommand::class, ['--force' => true])
        ->assertExitCode(Command::SUCCESS);

    // First Arrange
    $firstEnv = Dotenv::parse(file_get_contents($this->app->environmentFilePath()));

    $firstAppKey = $firstEnv['APP_KEY'];
    $firstAppPrevKeys = explode(',', $firstEnv['APP_PREVIOUS_KEYS'] ?? '');

    // First Assert
    expect($firstAppKey)->not->toBe($zeroAppKey)
        ->and($firstAppKey)->toBe(config('app.key'))
        ->and($firstAppPrevKeys)->toBe(config('app.previous_keys'))
        ->and(count($firstAppPrevKeys))->toBe(1)
        ->and($zeroAppKey)->toBeIn($firstAppPrevKeys);

    // Second Act
    $this->artisan(KeyRotateCommand::class, ['--force' => true])
        ->assertExitCode(Command::SUCCESS);

    // Second Arrange
    $secondEnv = Dotenv::parse(file_get_contents($this->app->environmentFilePath()));
    $secondAppKey = $secondEnv['APP_KEY'];
    $secondAppPrevKeys = explode(',', $secondEnv['APP_PREVIOUS_KEYS'] ?? '');

    // Second Assert
    expect($secondAppKey)->not->toBe($firstAppKey)
        ->and($secondAppKey)->toBe(config('app.key'))
        ->and($secondAppPrevKeys)->toBe(config('app.previous_keys'))
        ->and(count($secondAppPrevKeys))->toBe(2)
        ->and($zeroAppKey)->toBeIn($secondAppPrevKeys)
        ->and($firstAppKey)->toBeIn($secondAppPrevKeys);
});

it('has pre-seeded DB tables', function () {
    expect(Schema::hasTable('secrets'))->toBeTrue()
        ->and(Schema::hasTable('users'))
        ->and(Secret::count())->toBe(1);
});

it('does throw the DecryptExceptions', function () {
    $this->artisan('key:generate', ['--force' => true]);

    expect(fn () => Secret::find(1)->encrypted)
        ->toThrow(DecryptException::class);
});

it('does not throw the DecryptExceptions', function () {
    expect(fn () => Secret::find(1)->encrypted)
        ->not->toThrow(DecryptException::class);
});

it('does handle Model updates with the Listener', function () {
    // Arrange
    KeyRotate::withListener()
        ->withModel(Secret::class)
        ->withCast(CustomCast::class);

    // Before
    $secretBefore = Secret::find(1);
    $rawSecretBefore = DB::select('SELECT * FROM secrets WHERE id = ?;', [1])[0];

    // Act
    $this->artisan(KeyRotateCommand::class, ['--force' => true])
        ->assertExitCode(Command::SUCCESS);

    // After
    $secretAfter = Secret::find(1);
    $rawSecretAfter = DB::select('SELECT * FROM secrets WHERE id = ?;', [1])[0];

    // Assert fields after update are the same as before and their values are equals to ones from the migration
    expect($secretAfter)->not->toBe($secretBefore)
        ->and($secretAfter->encrypted)->toBe($secretBefore->encrypted)
        ->and($secretAfter->encrypted)->toBe('text')
        ->and($secretAfter->encrypted_array)->toBe($secretBefore->encrypted_array)
        ->and($secretAfter->encrypted_array)->toBeArray()
        ->and($secretAfter->encrypted_array)->toBe(['array'])
        ->and($secretAfter->encrypted_collection->toArray())->toBe($secretBefore->encrypted_collection->toArray())
        ->and($secretAfter->encrypted_collection)->toBeInstanceOf(Collection::class)
        ->and($secretAfter->encrypted_collection->toArray())->toBe(['collection'])
        ->and($secretAfter->encrypted_object)->toBeObject()
        ->and($secretAfter->as_encrypted_array_object)->toBeObject()
        ->and($secretAfter->as_encrypted_array_object->toArray())->toBeArray()
        ->and($secretAfter->as_encrypted_array_object->toArray())->toBe(['array'])
        ->and($secretAfter->as_encrypted_collection)->toBeInstanceOf(Collection::class)
        ->and($secretAfter->as_encrypted_collection->toArray())->toBe(['collection']);

    // Assert raw fields after update are different
    $fields = [
        'encrypted',
        'encrypted_array',
        'encrypted_collection',
        'encrypted_object',
        'as_encrypted_array_object',
        'as_encrypted_collection',
        'custom',
    ];

    foreach ($fields as $field) {
        expect($rawSecretBefore->{$field})->not->toBe($rawSecretAfter->{$field});
    }
});

it('does not handle Model updates without the Listener', function () {
    // Before
    $secretBefore = Secret::find(1);
    $rawSecretBefore = DB::select('SELECT * FROM secrets WHERE id = ?;', [1])[0];

    // Act
    $this->artisan(KeyRotateCommand::class, ['--force' => true])
        ->assertExitCode(Command::SUCCESS);

    // After
    $secretAfter = Secret::find(1);
    $rawSecretAfter = DB::select('SELECT * FROM secrets WHERE id = ?;', [1])[0];

    // Assert
    expect($secretAfter)->not->toBe($secretBefore);

    // Assert raw fields after update are the same as before
    $fields = [
        'encrypted',
        'encrypted_array',
        'encrypted_collection',
        'encrypted_object',
        'as_encrypted_array_object',
        'as_encrypted_collection',
        'custom',
    ];

    foreach ($fields as $field) {
        expect($rawSecretBefore->{$field})->toBe($rawSecretAfter->{$field})
            ->and(fn () => $secretBefore->{$field})->not->toThrow(DecryptException::class)
            ->and(fn () => $secretAfter->{$field})->not->toThrow(DecryptException::class);
    }
});

it('does handle Model updates for extended fields and casts', function () {
    // Arrange
    KeyRotate::withListener()
        ->withModel(Secret::class)
        // ->withModelFields(Secret::class, ['secret'])
        ->withCast(CustomCast::class);

    // Before
    $secretBefore = Secret::find(1);
    $rawSecretBefore = DB::select('SELECT * FROM secrets WHERE id = ?;', [1])[0];

    // Act
    $this->artisan(KeyRotateCommand::class, ['--force' => true])
        ->assertExitCode(Command::SUCCESS);

    // After
    $secretAfter = Secret::find(1);
    $rawSecretAfter = DB::select('SELECT * FROM secrets WHERE id = ?;', [1])[0];

    expect($secretAfter)->not->toBe($secretBefore)
        ->and($rawSecretBefore->custom)->not->toBe($rawSecretAfter->custom)
        ->and(fn () => $secretBefore->custom)->not->toThrow(DecryptException::class)
        ->and(fn () => $secretAfter->custom)->not->toThrow(DecryptException::class);
});

it('does not handle Model updates for cut fields and casts', function () {
    // Arrange
    KeyRotate::withListener()
        ->withDir(workbench_path('app'), 'Workbench\\App\\')
        ->withDir(workbench_path('database'), 'Workbench\\Database\\')
        ->withoutModel(User::class)
        ->withoutModelFields(Secret::class, ['encrypted'])
        ->withoutCast(AsEncryptedArrayObject::class);

    // Before
    $secretBefore = Secret::find(1);
    $rawSecretBefore = DB::select('SELECT * FROM secrets WHERE id = ?;', [1])[0];

    // Act
    $this->artisan(KeyRotateCommand::class, ['--force' => true])
        ->assertExitCode(Command::SUCCESS);

    // After
    $secretAfter = Secret::find(1);
    $rawSecretAfter = DB::select('SELECT * FROM secrets WHERE id = ?;', [1])[0];

    expect($secretAfter)->not->toBe($secretBefore)
        ->and($rawSecretBefore->encrypted)->toBe($rawSecretAfter->encrypted)
        ->and(fn () => $secretBefore->encrypted)->not->toThrow(DecryptException::class)
        ->and(fn () => $secretAfter->encrypted)->not->toThrow(DecryptException::class)
        ->and($rawSecretBefore->as_encrypted_array_object)->toBe($rawSecretAfter->as_encrypted_array_object)
        ->and(fn () => $secretBefore->as_encrypted_array_object)->not->toThrow(DecryptException::class)
        ->and(fn () => $secretAfter->as_encrypted_array_object)->not->toThrow(DecryptException::class);
});
