Gem::Specification.new do |s|
  s.name        = 'paratope'
  s.version     = '0.1.1'
  s.date        = '2016-08-18'
  s.summary     = "Library to maintain AWS security groups"
  s.description = "Library to audit, create, or update AWS security groups "\
                  "based on a Ruby config file."
  s.authors     = ["Anna Pham"]
  s.email       = 'annuhlyze@gmail.com'
  s.files       = ["lib/paratope.rb"]
  s.homepage    =
    'http://rubygems.org/gems/paratope'
  s.license       = 'Apache-2.0'
  s.add_runtime_dependency 'fog-aws', '~> 0.7.6'
end