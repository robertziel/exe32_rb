require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs   << "lib" << "test"
  t.pattern = "test/**/*_test.rb"
  t.verbose = false
end

task default: :test

desc "Build the bundled i386 hello-world fixture (examples/hello.exe)"
task :hello do
  ruby "tools/build_hello.rb"
end

desc "Build the bundled fixture and run it through the emulator"
task demo: :hello do
  sh "./exe/exe32_rb", "run", "examples/hello.exe"
end
