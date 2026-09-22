import { useState, type ReactNode } from 'react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { DropdownMenuItem } from '@/components/ui/dropdown-menu'

interface Props {
  title: string
  description?: ReactNode
  onConfirm: () => void
  children: ReactNode
  destructive?: boolean
  confirmLabel?: string
  asMenuItem?: boolean
  variant?: React.ComponentProps<typeof Button>['variant']
  size?: React.ComponentProps<typeof Button>['size']
  disabled?: boolean
  'aria-label'?: string
}

/** A button (or dropdown item) that asks for confirmation before acting. */
export function ConfirmButton({
  title,
  description,
  onConfirm,
  children,
  destructive,
  confirmLabel = 'Continue',
  asMenuItem,
  variant = 'ghost',
  size,
  disabled,
  ...rest
}: Props) {
  const [open, setOpen] = useState(false)
  return (
    <>
      {asMenuItem ? (
        <DropdownMenuItem
          variant={destructive ? 'destructive' : 'default'}
          onSelect={(e) => {
            e.preventDefault()
            setOpen(true)
          }}
        >
          {children}
        </DropdownMenuItem>
      ) : (
        <Button variant={variant} size={size} disabled={disabled} onClick={() => setOpen(true)} {...rest}>
          {children}
        </Button>
      )}
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{title}</AlertDialogTitle>
            {description && <AlertDialogDescription>{description}</AlertDialogDescription>}
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant={destructive ? 'destructive' : 'default'}
              onClick={() => {
                setOpen(false)
                onConfirm()
              }}
            >
              {confirmLabel}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
