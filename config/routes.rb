SafeBro::Engine.routes.draw do
  root "sessions#index"

  resources :sessions, only: %i[ index show ] do
    resources :audits, only: :create
  end

  get "flagged" => "flagged_commands#index", as: :flagged_commands
  get "unlocks" => "unlocks#index", as: :unlocks
  get "rules" => "rules#show", as: :rules
end
