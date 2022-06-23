require 'json'
require 'set'
require 'date'

# Arg 1 is the rules json genetrated from sdc-cli
rules = JSON.parse(File.read(ARGV[0]))

# Arg 2 is the layer file
layer = JSON.parse(File.read(ARGV[1]))

puts "Selecting Mitre related rules from input"
mitre_rules = rules.select { |item| not (item['tags'].select! {|tag| tag =~ /MITRE./}).nil? }

mitre_hash = {}
mitre_rules.each do |rule|
  rule['tags'].each do |tag|
    mitre = tag.split('_')[1]
    if mitre_hash[mitre].nil?
      mitre_hash[mitre] = Set.new
    end
    if mitre =~ /\w\d+\./
      parent = mitre.split('.')[0]
      if mitre_hash[parent].nil?
        mitre_hash[parent] = Set.new
        mitre_hash[parent] << rule['name']
     end
    end
    mitre_hash[mitre] << rule['name']
  end
end

puts "Adding Sysdig Secure rule data to the Mitre Att&ck layer"

#Mark the given technique as green, enabe it, and add the supporting Sysdig rules as a comment
layer['techniques'].each do |tech|
 if not mitre_hash[tech['techniqueID']].nil?
   tech['comment'] = mitre_hash[tech['techniqueID']].join(' | ')
   tech['color'] = '#a1d99b'
   tech['enabled'] = true
 end
end

#Set the date in the layer metadata
layer['description'] = "#{layer['description']} - #{DateTime.now.to_date}"

File.open("sysdig_secure_layer_#{DateTime.now.to_date}.json", 'w') { |file| file.write(JSON.pretty_generate(layer))}
puts "Wrote file sysdig_secure_layer_#{DateTime.now.to_date}.json"
