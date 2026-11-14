module SafeBro
  class ApplicationRecord < ActiveRecord::Base
    self.abstract_class = true
    self.table_name_prefix = "safe_bro_"
  end
end
