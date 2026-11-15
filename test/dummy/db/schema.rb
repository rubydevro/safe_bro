# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[7.1].define(version: 2026_11_14_000002) do
  create_table "safe_bro_audits", force: :cascade do |t|
    t.integer "session_id", null: false
    t.string "auditor", null: false
    t.integer "status", null: false
    t.text "notes"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["session_id"], name: "index_safe_bro_audits_on_session_id"
  end

  create_table "safe_bro_commands", force: :cascade do |t|
    t.integer "session_id", null: false
    t.integer "sensitive_access_id"
    t.text "statements"
    t.integer "status", default: 0, null: false
    t.text "flag_reason"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["sensitive_access_id"], name: "index_safe_bro_commands_on_sensitive_access_id"
    t.index ["session_id", "created_at"], name: "index_safe_bro_commands_on_session_id_and_created_at"
    t.index ["status"], name: "index_safe_bro_commands_on_status"
  end

  create_table "safe_bro_sensitive_accesses", force: :cascade do |t|
    t.integer "session_id", null: false
    t.string "resources", default: "all", null: false
    t.text "justification", null: false
    t.datetime "started_at", null: false
    t.datetime "ended_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["session_id"], name: "index_safe_bro_sensitive_accesses_on_session_id"
  end

  create_table "safe_bro_sessions", force: :cascade do |t|
    t.string "username", null: false
    t.text "reason", null: false
    t.string "source", default: "console", null: false
    t.string "hostname"
    t.integer "pid"
    t.integer "review_status", default: 0, null: false
    t.datetime "started_at", null: false
    t.datetime "ended_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "client_ip"
    t.index ["review_status", "started_at"], name: "index_safe_bro_sessions_on_review_status_and_started_at"
    t.index ["started_at"], name: "index_safe_bro_sessions_on_started_at"
    t.index ["username", "started_at"], name: "index_safe_bro_sessions_on_username_and_started_at"
  end

  create_table "secretives", force: :cascade do |t|
    t.text "name"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end
end
