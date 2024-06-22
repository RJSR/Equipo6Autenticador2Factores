<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Auth::routes();

Route::get('/home', [App\Http\Controllers\HomeController::class, 'index'])->name('home');
# Ruta del metodo login2FA en LoginController
Route::post('/{user}', 'App\Http\Controllers\Auth\LoginController@login2FA')->name('login.2fa');
