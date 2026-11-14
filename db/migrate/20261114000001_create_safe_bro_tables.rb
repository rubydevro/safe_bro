class CreateSafeBroTables < ActiveRecord::Migration[7.1]
  def change
    create_table :safe_bro_sessions do |t|
      t.string :username, null: false
      t.text :reason, null: false
      t.string :source, null: false, default: "console"
      t.string :hostname
      t.integer :pid
      t.integer :review_status, null: false, default: 0
      t.datetime :started_at, null: false
      t.datetime :ended_at

      t.timestamps

      t.index :started_at
      t.index [ :username, :started_at ]
      t.index [ :review_status, :started_at ]
    end

    create_table :safe_bro_sensitive_accesses do |t|
      t.references :session, null: false, index: true
      t.string :resources, null: false, default: "all"
      t.text :justification, null: false
      t.datetime :started_at, null: false
      t.datetime :ended_at

      t.timestamps
    end

    create_table :safe_bro_commands do |t|
      t.references :session, null: false, index: false
      t.references :sensitive_access, index: true
      t.text :statements
      t.integer :status, null: false, default: 0
      t.text :flag_reason

      t.timestamps

      t.index [ :session_id, :created_at ]
      t.index :status
    end

    create_table :safe_bro_audits do |t|
      t.references :session, null: false, index: true
      t.string :auditor, null: false
      t.integer :status, null: false
      t.text :notes

      t.timestamps
    end
  end
end
