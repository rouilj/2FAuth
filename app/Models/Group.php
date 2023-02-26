<?php

namespace App\Models;

use App\Events\GroupDeleting;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Log;

/**
 * @property int $twofaccounts_count
 */
class Group extends Model
{
    use HasFactory;

    /**
     * model's array form.
     *
     * @var string[]
     */
    protected $fillable = ['name'];

    /**
     * The accessors to append to the model's array form.
     *
     * @var array
     */
    protected $appends = [];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array<int, string>
     */
    protected $hidden = ['created_at', 'updated_at'];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'twofaccounts_count' => 'integer',
    ];

    /**
     * The event map for the model.
     *
     * @var array
     */
    protected $dispatchesEvents = [
        'deleting' => GroupDeleting::class,
    ];

    /**
     * Override The "booting" method of the model
     *
     * @return void
     */
    protected static function boot()
    {
        parent::boot();

        static::deleted(function (object $model) {
            // @codeCoverageIgnoreStart
            Log::info(sprintf('Group "%s" deleted', var_export($model->name, true)));
            // @codeCoverageIgnoreEnd
        });
    }

    /**
     * Get the TwoFAccounts of the group.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany<TwoFAccount>
     */
    public function twofaccounts()
    {
        return $this->hasMany(\App\Models\TwoFAccount::class);
    }

   /**
    * Get the user that owns the group.
    *
    * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\App\Models\User, \App\Models\Group>
    */
   public function user()
   {
       return $this->belongsTo(\App\Models\User::class);
   }
}
