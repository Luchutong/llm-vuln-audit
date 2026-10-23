<?php
class DispatchJob {
    public string $command = 'printf inventory-ready';
    public function __wakeup(): void { echo (string)shell_exec($this->command); }
}
